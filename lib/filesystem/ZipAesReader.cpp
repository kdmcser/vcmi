/*
 * ZipAesReader.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "ZipAesReader.h"

#include <cstring>

VCMI_LIB_NAMESPACE_BEGIN

namespace ZipAes
{

namespace
{

/// extra field 里 AES 信息的表头 ID
constexpr std::uint16_t aesExtraFieldId = 0x9901;

/// 中央目录项与本地头的固定部分长度
constexpr std::size_t centralDirectoryRecordLength = 46;
constexpr std::size_t localHeaderLength = 30;

/// 两个结构开头的签名
constexpr std::uint32_t centralDirectorySignature = 0x02014b50;
constexpr std::uint32_t localHeaderSignature = 0x04034b50;

/// 需要读 zip64 extra field 的哨兵值，这种条目这里没做支持
constexpr std::uint32_t zip64Marker = 0xffffffffu;

/// 每次处理的块大小。放在栈上，取小一点避免深调用链上爆栈。
constexpr std::size_t chunkSize = 16 * 1024;

std::uint16_t readLittleEndian16(const std::uint8_t * data)
{
	return static_cast<std::uint16_t>(data[0])
	     | static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[1]) << 8);
}

std::uint32_t readLittleEndian32(const std::uint8_t * data)
{
	return static_cast<std::uint32_t>(data[0])
	     | (static_cast<std::uint32_t>(data[1]) << 8)
	     | (static_cast<std::uint32_t>(data[2]) << 16)
	     | (static_cast<std::uint32_t>(data[3]) << 24);
}

}

ZipAesReader::ZipAesReader(const zlib_filefunc64_def & fileApi, const std::string & archivePath,
                           std::uint64_t centralDirectoryOffset, const std::string & password)
	: fileApi(fileApi)
{
	stream = fileApi.zopen64_file(fileApi.opaque, archivePath.c_str(), ZLIB_FILEFUNC_MODE_READ);
	if(stream == nullptr)
	{
		failed = true;
		return;
	}

	// 中央目录项：compressed size 在偏移 20，文件名长度 28、extra 长度 30、本地头偏移 42
	std::uint8_t record[centralDirectoryRecordLength];
	if(!seekAndRead(centralDirectoryOffset, record, sizeof(record))
	   || readLittleEndian32(record) != centralDirectorySignature)
	{
		failed = true;
		return;
	}

	const std::uint32_t compressedSize = readLittleEndian32(record + 20);
	const std::uint16_t nameLength = readLittleEndian16(record + 28);
	const std::uint16_t extraLength = readLittleEndian16(record + 30);
	const std::uint32_t localHeaderOffset = readLittleEndian32(record + 42);

	if(compressedSize == zip64Marker || localHeaderOffset == zip64Marker)
	{
		failed = true;
		return;
	}

	std::vector<std::uint8_t> extraField(extraLength);
	if(extraLength > 0
	   && !seekAndRead(centralDirectoryOffset + centralDirectoryRecordLength + nameLength,
	                   extraField.data(), extraLength))
	{
		failed = true;
		return;
	}

	if(!parseExtraField(extraField.data(), extraField.size()))
	{
		failed = true;
		return;
	}

	// 本地头：文件名长度在偏移 26，extra 长度 28，固定部分 30 字节
	std::uint8_t localHeader[localHeaderLength];
	if(!seekAndRead(localHeaderOffset, localHeader, sizeof(localHeader))
	   || readLittleEndian32(localHeader) != localHeaderSignature)
	{
		failed = true;
		return;
	}

	const std::uint64_t dataOffset = static_cast<std::uint64_t>(localHeaderOffset) + localHeaderLength
	                               + readLittleEndian16(localHeader + 26)
	                               + readLittleEndian16(localHeader + 28);

	const std::size_t saltSize = saltLength(strength);
	const std::uint64_t overhead = static_cast<std::uint64_t>(saltSize) + verifyValueLength + authCodeLength;

	if(compressedSize < overhead)
	{
		failed = true;
		return;
	}

	std::uint8_t saltBuffer[16];
	std::uint8_t verifyBuffer[verifyValueLength];

	if(!seek(dataOffset) || !readExact(saltBuffer, saltSize) || !readExact(verifyBuffer, verifyValueLength))
	{
		failed = true;
		return;
	}

	deriveAesKeys(strength, reinterpret_cast<const std::uint8_t *>(password.data()), password.size(),
	              saltBuffer, keyMaterial);

	// 密码不对就没必要继续算了
	if(verifyBuffer[0] != keyMaterial.verifyValue[0] || verifyBuffer[1] != keyMaterial.verifyValue[1])
	{
		failed = true;
		return;
	}

	aesCtrInit(cipher, strength, keyMaterial.encryptionKey);
	hmacSha1Init(hmac, keyMaterial.authenticationKey, keyLength(strength));

	remainingCipher = compressedSize - overhead;

	if(realMethod == Z_DEFLATED)
	{
		inflateStream = z_stream{};
		if(inflateInit2(&inflateStream, -MAX_WBITS) != Z_OK)
		{
			failed = true;
			return;
		}
		inflateActive = true;
	}
	else if(realMethod != 0)
	{
		// 除了「存储」和 deflate，其他压缩方式没做支持
		failed = true;
		return;
	}
}

ZipAesReader::~ZipAesReader()
{
	if(inflateActive)
		inflateEnd(&inflateStream);

	if(stream != nullptr)
		fileApi.zclose_file(fileApi.opaque, stream);

	// 密钥材料用完立刻清掉
	secureErase(&keyMaterial, sizeof(keyMaterial));
	secureErase(&cipher, sizeof(cipher));
	secureErase(&hmac, sizeof(hmac));
}

si64 ZipAesReader::read(ui8 * data, si64 size)
{
	if(failed)
		return -1;

	if(size <= 0)
		return 0;

	si64 produced = 0;

	while(produced < size)
	{
		if(plainOffset < plainBuffer.size())
		{
			const std::size_t take = std::min<std::size_t>(plainBuffer.size() - plainOffset,
			                                                static_cast<std::size_t>(size - produced));
			std::memcpy(data + produced, plainBuffer.data() + plainOffset, take);
			plainOffset += take;
			produced += static_cast<si64>(take);
			continue;
		}

		if(finished)
			break;

		if(!fillPlainBuffer())
			break;
	}

	return produced;
}

bool ZipAesReader::parseExtraField(const std::uint8_t * data, std::size_t length)
{
	std::size_t offset = 0;

	while(offset + 4 <= length)
	{
		const std::uint16_t headerId = readLittleEndian16(data + offset);
		const std::uint16_t dataSize = readLittleEndian16(data + offset + 2);

		if(offset + 4 + dataSize > length)
			return false;

		if(headerId == aesExtraFieldId)
		{
			// 布局：version(2) + "AE"(2) + strength(1) + 真实压缩方法(2)
			if(dataSize < 7)
				return false;

			const std::uint8_t strengthValue = data[offset + 4 + 4];
			if(strengthValue < 1 || strengthValue > 3)
				return false;

			strength = static_cast<Strength>(strengthValue);
			realMethod = static_cast<int>(readLittleEndian16(data + offset + 4 + 5));
			return true;
		}

		offset += 4 + dataSize;
	}

	return false;
}

bool ZipAesReader::seek(std::uint64_t offset)
{
	return fileApi.zseek64_file(fileApi.opaque, stream, offset, ZLIB_FILEFUNC_SEEK_SET) == 0;
}

bool ZipAesReader::readExact(std::uint8_t * data, std::size_t length)
{
	std::size_t offset = 0;

	while(offset < length)
	{
		const uLong readSize = fileApi.zread_file(fileApi.opaque, stream, data + offset,
		                                          static_cast<uLong>(length - offset));
		if(readSize == 0)
			return false;

		offset += static_cast<std::size_t>(readSize);
	}

	return true;
}

bool ZipAesReader::seekAndRead(std::uint64_t offset, std::uint8_t * data, std::size_t length)
{
	return seek(offset) && readExact(data, length);
}

bool ZipAesReader::fillPlainBuffer()
{
	plainBuffer.clear();
	plainOffset = 0;

	std::uint8_t cipherChunk[chunkSize];

	while(plainBuffer.empty() && !finished && !failed)
	{
		if(remainingCipher == 0)
		{
			finishEntry();
			break;
		}

		const std::uint64_t want = std::min<std::uint64_t>(remainingCipher, sizeof(cipherChunk));
		const uLong readSize = fileApi.zread_file(fileApi.opaque, stream, cipherChunk,
		                                          static_cast<uLong>(want));

		if(readSize == 0)
		{
			failed = true;
			break;
		}

		// 认证码算的是密文，所以先喂 HMAC 再解密
		hmacSha1Update(hmac, cipherChunk, static_cast<std::size_t>(readSize));
		aesCtrCrypt(cipher, cipherChunk, static_cast<std::size_t>(readSize));

		remainingCipher -= static_cast<std::uint64_t>(readSize);

		if(inflateActive)
		{
			if(!inflateChunk(cipherChunk, static_cast<std::size_t>(readSize)))
			{
				failed = true;
				break;
			}
		}
		else
		{
			plainBuffer.insert(plainBuffer.end(), cipherChunk, cipherChunk + readSize);
		}
	}

	secureErase(cipherChunk, sizeof(cipherChunk));

	return !plainBuffer.empty();
}

bool ZipAesReader::inflateChunk(const std::uint8_t * data, std::size_t length)
{
	inflateStream.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(data));
	inflateStream.avail_in = static_cast<uInt>(length);

	std::uint8_t output[chunkSize];

	while(inflateStream.avail_in > 0)
	{
		inflateStream.next_out = output;
		inflateStream.avail_out = sizeof(output);

		const int result = inflate(&inflateStream, Z_NO_FLUSH);
		if(result != Z_OK && result != Z_STREAM_END && result != Z_BUF_ERROR)
			return false;

		const std::size_t produced = sizeof(output) - inflateStream.avail_out;
		if(produced > 0)
			plainBuffer.insert(plainBuffer.end(), output, output + produced);

		if(result == Z_STREAM_END)
			break;

		// 既没产出也没消耗输入，说明还缺数据，等下一块
		if(result == Z_BUF_ERROR && produced == 0)
			break;
	}

	return true;
}

void ZipAesReader::finishEntry()
{
	std::uint8_t storedAuthCode[authCodeLength];
	std::uint8_t computedAuthCode[20];

	// 认证码在数据末尾；调用方没把条目读完时可能取不到，那就放弃这次校验
	if(readExact(storedAuthCode, authCodeLength))
	{
		hmacSha1Final(hmac, computedAuthCode);
		authenticationValid = std::memcmp(storedAuthCode, computedAuthCode, authCodeLength) == 0;

		secureErase(computedAuthCode, sizeof(computedAuthCode));
	}

	finished = true;
}

}

VCMI_LIB_NAMESPACE_END
