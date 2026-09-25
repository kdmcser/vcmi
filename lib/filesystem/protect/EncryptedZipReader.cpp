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

/// Header ID of the AES information within the extra field
constexpr std::uint16_t aesExtraFieldId = 0x9901;

/// Compression method number of an AES entry
constexpr std::uint16_t aesCompressionMethod = 99;

/// Fixed portion lengths of the central directory record and the local header
constexpr std::size_t centralDirectoryRecordLength = 46;
constexpr std::size_t localHeaderLength = 30;

/// Length of the ZipCrypto encryption header
constexpr std::size_t zipCryptoHeaderLength = 12;

/// Signatures at the start of the two structures
constexpr std::uint32_t centralDirectorySignature = 0x02014b50;
constexpr std::uint32_t localHeaderSignature = 0x04034b50;

/// Sentinel value indicating that a zip64 extra field must be read; such entries are not supported here
constexpr std::uint32_t zip64Marker = 0xffffffffu;

/// Hands the password bytes produced by the protected bytecode to the caller.
/// AES PBKDF2 replays them every time the HMAC key block is rebuilt, and a full
/// password is never retained at any point.
bool replayPasswordBytes(void * context, ZipAes::PasswordByteConsumer consumer, void * consumerContext)
{
	return derivePasswordBytes(consumer, consumerContext);
}

/// Chunk size processed per iteration. Kept on the stack and made small to avoid stack overflow on deep call chains.
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

EncryptedZipReader::EncryptedZipReader(const zlib_filefunc64_def & fileApi, const void * archivePath,
                                       std::uint64_t centralDirectoryOffset)
	: fileApi(fileApi)
{
	// The path is forwarded as-is per the fileApi contract: on Windows the
	// implementation expects a wide-character path, so std::string::c_str() must never be used here
	stream = fileApi.zopen64_file(fileApi.opaque, archivePath, ZLIB_FILEFUNC_MODE_READ);
	if(stream == nullptr)
	{
		failed = true;
		return;
	}

	// The concrete reason for failure is recorded by the caller (CZipLoader) along with the entry name and archive name
	if(!openEntry(centralDirectoryOffset))
		failed = true;
}

EncryptedZipReader::~EncryptedZipReader()
{
	if(inflateActive)
		inflateEnd(&inflateStream);

	if(stream != nullptr)
		fileApi.zclose_file(fileApi.opaque, stream);

	// Wipe the key material as soon as it is no longer needed
	ZipAes::secureErase(&zipCryptoKeys, sizeof(zipCryptoKeys));
	ZipAes::secureErase(&aesCtr, sizeof(aesCtr));
	ZipAes::secureErase(&aesHmac, sizeof(aesHmac));
}

bool EncryptedZipReader::openEntry(std::uint64_t centralDirectoryOffset)
{
	// Central directory record: method at offset 10, compressed size 20,
	// name length 28, extra length 30, local header offset 42
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

	// Local header: name length at offset 26, extra length 28, fixed part 30 bytes
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

		// The password is produced byte by byte by the protected bytecode. PBKDF2
		// replays it every time the HMAC key block is rebuilt, and at no point is the
		// password assembled into a complete copy.
		ZipAes::PasswordByteSource password;
		password.context = nullptr;
		password.replay = &replayPasswordBytes;

		ZipAes::AesKeyMaterial keyMaterial;
		ZipAes::deriveAesKeys(aesStrength, password, saltBuffer, keyMaterial);

		if(verifyBuffer[0] != keyMaterial.verifyValue[0] || verifyBuffer[1] != keyMaterial.verifyValue[1])
		{
			ZipAes::secureErase(&keyMaterial, sizeof(keyMaterial));
			return false;
		}

		remainingCipher = compressedSize - overhead;

		// The authentication code is at the end of the data, and once data has been
		// handed out it cannot be taken back, so while the key is still in hand the
		// whole ciphertext is scanned and verified first; only after it passes is the
		// data allowed to be read out to the caller.
		const std::uint64_t cipherOffset = dataOffset
		                                 + static_cast<std::uint64_t>(saltSize)
		                                 + ZipAes::verifyValueLength;

		const bool authenticated = precheckAuthentication(
		    keyMaterial.authenticationKey, ZipAes::keyLength(aesStrength), cipherOffset);

		if(authenticated)
		{
			ZipAes::aesCtrInit(aesCtr, aesStrength, keyMaterial.encryptionKey);
			ZipAes::hmacSha1Init(aesHmac, keyMaterial.authenticationKey, ZipAes::keyLength(aesStrength));
		}

		ZipAes::secureErase(&keyMaterial, sizeof(keyMaterial));

		if(!authenticated)
			return false;
	}
	else
	{
		cipher = Cipher::ZipCrypto;
		compressionMethod = method;

		if(compressedSize < zipCryptoHeaderLength)
			return false;

		// The key state is computed directly by the bytecode; the plaintext password never passes through here nor lands in a buffer
		deriveZipCryptoKeys(zipCryptoKeys);

		// First decrypt the 12-byte encryption header: its content is unused, but it advances the key state
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
		// No compression methods other than "stored" and deflate are supported
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
			// Layout: version(2) + "AE"(2) + strength(1) + actual compression method(2)
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
		// The AES authentication code is computed over the ciphertext, so the HMAC must be fed before decrypting
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

		// Neither produced output nor consumed input, meaning more data is needed; wait for the next chunk
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

bool EncryptedZipReader::precheckAuthentication(const std::uint8_t * authenticationKey,
                                                std::size_t keyLength, std::uint64_t cipherOffset)
{
	ZipAes::HmacSha1Context hmac;
	ZipAes::hmacSha1Init(hmac, authenticationKey, keyLength);

	std::vector<ui8> buffer(chunkSize);
	std::uint64_t left = remainingCipher;

	while(left > 0)
	{
		const std::uint64_t take = std::min<std::uint64_t>(left, static_cast<std::uint64_t>(buffer.size()));

		if(!readExact(buffer.data(), static_cast<std::size_t>(take)))
			return false;

		ZipAes::hmacSha1Update(hmac, buffer.data(), static_cast<std::size_t>(take));
		left -= take;
	}

	std::uint8_t storedAuthCode[ZipAes::authCodeLength];
	if(!readExact(storedAuthCode, ZipAes::authCodeLength))
		return false;

	std::uint8_t computedAuthCode[20];
	ZipAes::hmacSha1Final(hmac, computedAuthCode);

	const bool valid = std::memcmp(storedAuthCode, computedAuthCode, ZipAes::authCodeLength) == 0;

	ZipAes::secureErase(&hmac, sizeof(hmac));
	ZipAes::secureErase(computedAuthCode, sizeof(computedAuthCode));
	ZipAes::secureErase(buffer.data(), buffer.size());

	// Seek back to the start of the ciphertext: the actual read decrypts it again from the beginning
	return valid && seek(cipherOffset);
}

void EncryptedZipReader::finishEntry()
{
	// The authentication code was already verified when the entry was opened (see
	// precheckAuthentication); reaching here only marks this data as fully read
	finished = true;
}

}

VCMI_LIB_NAMESPACE_END
