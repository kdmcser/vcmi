/*
 * EncryptedZipReader.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "EncryptedZipReader.h"

#include "PasswordProgram.h"

#include <cstring>
#include <vector>

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{

namespace
{

/// extra field 里 AES 信息的表头 ID
constexpr std::uint16_t aesExtraFieldId = 0x9901;

/// AES 条目的压缩方法编号
constexpr std::uint16_t aesCompressionMethod = 99;

/// 中央目录项与本地头的固定部分长度
constexpr std::size_t centralDirectoryRecordLength = 46;
constexpr std::size_t localHeaderLength = 30;

/// ZipCrypto 的加密头长度
constexpr std::size_t zipCryptoHeaderLength = 12;

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

EncryptedZipReader::EncryptedZipReader(const zlib_filefunc64_def & fileApi, const std::string & archivePath,
                                       std::uint64_t centralDirectoryOffset)
	: fileApi(fileApi)
{
	stream = fileApi.zopen64_file(fileApi.opaque, archivePath.c_str(), ZLIB_FILEFUNC_MODE_READ);
	if(stream == nullptr)
	{
		failed = true;
		return;
	}

	if(!openEntry(centralDirectoryOffset))
		failed = true;
}

EncryptedZipReader::~EncryptedZipReader()
{
	if(inflateActive)
		inflateEnd(&inflateStream);

	if(stream != nullptr)
		fileApi.zclose_file(fileApi.opaque, stream);

	// 密钥材料用完立刻清掉
	ZipAes::secureErase(&zipCryptoKeys, sizeof(zipCryptoKeys));
	ZipAes::secureErase(&aesCtr, sizeof(aesCtr));
	ZipAes::secureErase(&aesHmac, sizeof(aesHmac));
}

bool EncryptedZipReader::openEntry(std::uint64_t centralDirectoryOffset)
{
	// 中央目录项：method 在偏移 10，compressed size 20，
	// 文件名长度 28、extra 长度 30、本地头偏移 42
	std::uint8_t record[centralDirectoryRecordLength];
	if(!seekAndRead(centralDirectoryOffset, record, sizeof(record))
	   || readLittleEndian32(record) != centralDirectorySignature)
		return false;

	const std::uint16_t method = readLittleEndian16(record + 10);
	const std::uint32_t compressedSize = readLittleEndian32(record + 20);
	const std::uint16_t nameLength = readLittleEndian16(record + 28);
	const std::uint16_t extraLength = readLittleEndian16(record + 30);
	const std::uint32_t localHeaderOffset = readLittleEndian32(record + 42);

	if(compressedSize == zip64Marker || localHeaderOffset == zip64Marker)
		return false;

	std::vector<std::uint8_t> extraField(extraLength);
	if(extraLength > 0
	   && !seekAndRead(centralDirectoryOffset + centralDirectoryRecordLength + nameLength,
	                   extraField.data(), extraLength))
		return false;

	// 本地头：文件名长度在偏移 26，extra 长度 28，固定部分 30 字节
	std::uint8_t localHeader[localHeaderLength];
	if(!seekAndRead(localHeaderOffset, localHeader, sizeof(localHeader))
	   || readLittleEndian32(localHeader) != localHeaderSignature)
		return false;

	const std::uint64_t dataOffset = static_cast<std::uint64_t>(localHeaderOffset) + localHeaderLength
	                               + readLittleEndian16(localHeader + 26)
	                               + readLittleEndian16(localHeader + 28);

	if(!seek(dataOffset))
		return false;

	if(method == aesCompressionMethod)
	{
		cipher = Cipher::Aes;

		if(!parseAesExtraField(extraField.data(), extraField.size()))
			return false;

		const std::size_t saltSize = ZipAes::saltLength(aesStrength);
		const std::uint64_t overhead = static_cast<std::uint64_t>(saltSize)
		                             + ZipAes::verifyValueLength + ZipAes::authCodeLength;

		if(compressedSize < overhead)
			return false;

		std::uint8_t saltBuffer[16];
		std::uint8_t verifyBuffer[ZipAes::verifyValueLength];

		if(!readExact(saltBuffer, saltSize) || !readExact(verifyBuffer, ZipAes::verifyValueLength))
			return false;

		// 密码来自受保护的字节码。PBKDF2 必须拿到密码原文，所以这条路无法避免
		// 明文短暂存在，好在窗口只到派生结束。
		std::string password = derivePassword();

		ZipAes::AesKeyMaterial keyMaterial;
		ZipAes::deriveAesKeys(aesStrength, reinterpret_cast<const std::uint8_t *>(password.data()),
		                      password.size(), saltBuffer, keyMaterial);

		eraseSecret(password);

		if(verifyBuffer[0] != keyMaterial.verifyValue[0] || verifyBuffer[1] != keyMaterial.verifyValue[1])
		{
			ZipAes::secureErase(&keyMaterial, sizeof(keyMaterial));
			return false;
		}

		ZipAes::aesCtrInit(aesCtr, aesStrength, keyMaterial.encryptionKey);
		ZipAes::hmacSha1Init(aesHmac, keyMaterial.authenticationKey, ZipAes::keyLength(aesStrength));

		ZipAes::secureErase(&keyMaterial, sizeof(keyMaterial));

		remainingCipher = compressedSize - overhead;
	}
	else
	{
		cipher = Cipher::ZipCrypto;
		compressionMethod = method;

		if(compressedSize < zipCryptoHeaderLength)
			return false;

		// 密钥状态直接由字节码算出来，密码明文不经过这里、也不落缓冲区
		deriveZipCryptoKeys(zipCryptoKeys);

		// 先解掉 12 字节加密头：内容本身不用，但会推进密钥状态
		std::uint8_t header[zipCryptoHeaderLength];
		if(!readExact(header, sizeof(header)))
			return false;

		for(std::size_t i = 0; i < sizeof(header); ++i)
			zipCryptoDecryptByte(zipCryptoKeys, header[i]);

		ZipAes::secureErase(header, sizeof(header));

		remainingCipher = compressedSize - zipCryptoHeaderLength;
	}

	if(compressionMethod == Z_DEFLATED)
	{
		inflateStream = z_stream{};
		if(inflateInit2(&inflateStream, -MAX_WBITS) != Z_OK)
			return false;
		inflateActive = true;
	}
	else if(compressionMethod != 0)
	{
		// 除了「存储」和 deflate，其他压缩方式没做支持
		return false;
	}

	return true;
}

bool EncryptedZipReader::parseAesExtraField(const std::uint8_t * data, std::size_t length)
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

			aesStrength = static_cast<ZipAes::Strength>(strengthValue);
			compressionMethod = static_cast<int>(readLittleEndian16(data + offset + 4 + 5));
			return true;
		}

		offset += 4 + dataSize;
	}

	return false;
}

bool EncryptedZipReader::seek(std::uint64_t offset)
{
	return fileApi.zseek64_file(fileApi.opaque, stream, offset, ZLIB_FILEFUNC_SEEK_SET) == 0;
}

bool EncryptedZipReader::readExact(std::uint8_t * data, std::size_t length)
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

bool EncryptedZipReader::seekAndRead(std::uint64_t offset, std::uint8_t * data, std::size_t length)
{
	return seek(offset) && readExact(data, length);
}

void EncryptedZipReader::decryptChunk(std::uint8_t * data, std::size_t length)
{
	if(cipher == Cipher::ZipCrypto)
	{
		for(std::size_t i = 0; i < length; ++i)
			data[i] = zipCryptoDecryptByte(zipCryptoKeys, data[i]);
	}
	else
	{
		// AES 的认证码算的是密文，所以要先喂 HMAC 再解密
		ZipAes::hmacSha1Update(aesHmac, data, length);
		ZipAes::aesCtrCrypt(aesCtr, data, length);
	}
}

bool EncryptedZipReader::fillPlainBuffer()
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

		decryptChunk(cipherChunk, static_cast<std::size_t>(readSize));

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

	ZipAes::secureErase(cipherChunk, sizeof(cipherChunk));

	return !plainBuffer.empty();
}

bool EncryptedZipReader::inflateChunk(const std::uint8_t * data, std::size_t length)
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

si64 EncryptedZipReader::read(ui8 * data, si64 size)
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

void EncryptedZipReader::finishEntry()
{
	// 只有 AES 有认证码，且它在数据末尾；调用方没读完时可能取不到，
	// 那就放弃这次校验（认证码是防篡改用的，不是防提取的手段）。
	if(cipher == Cipher::Aes)
	{
		std::uint8_t storedAuthCode[ZipAes::authCodeLength];
		std::uint8_t computedAuthCode[20];

		if(readExact(storedAuthCode, ZipAes::authCodeLength))
		{
			ZipAes::hmacSha1Final(aesHmac, computedAuthCode);
			authenticationValid =
			    std::memcmp(storedAuthCode, computedAuthCode, ZipAes::authCodeLength) == 0;
			authenticationChecked = true;

			ZipAes::secureErase(computedAuthCode, sizeof(computedAuthCode));
		}
	}

	finished = true;
}

void EncryptedZipReader::finishEntryIfComplete()
{
	// 密文没读完就不碰认证码：位置不对，也谈不上校验
	if(finished || failed || remainingCipher != 0)
		return;

	finishEntry();
}

}

VCMI_LIB_NAMESPACE_END
