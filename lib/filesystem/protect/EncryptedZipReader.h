/*
 * EncryptedZipReader.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include "StdInc.h"
#include "../ZipAesCrypto.h"
#include "ZipCrypto.h"

#include <vector>

// Kept in sync with MinizipExtensions.h: prefer minizip-ng, fall back to legacy minizip.
// Only its IO callback types are used here; its entry reading interface is not.
#if __has_include(<minizip-ng/unzip.h>)
#include <minizip-ng/unzip.h>
#else
#include <minizip/unzip.h>
#endif

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{

/// Reads encrypted zip entries, supporting both ZipCrypto and WinZip AES.
///
/// Why neither case is delegated to minizip:
///   * An AES entry has method 99, while minizip only recognizes 0 / 8 / 12, so even
///     when opened in raw mode it returns UNZ_BADZIPFILE; the platforms use prebuilt
///     dependency packages, so patching minizip is not realistic.
///   * For ZipCrypto, delegating to minizip would require passing the plaintext
///     password into unzOpenCurrentFilePassword, which is exactly what an attacker
///     wants. Instead, the key state is computed directly by the protected bytecode,
///     so the plaintext password never lands in any buffer.
///
/// Therefore the zip structure is walked manually: from the central directory
/// record, locate the local header and skip the filename and extra field to obtain
/// the entry's encrypted data.
class EncryptedZipReader
{
public:
	/// centralDirectoryOffset comes from the pos_in_zip_directory returned by unzGetFilePos64()
	///
	/// archivePath must be passed as-is, in the type expected by the fileApi contract;
	/// no conversion is done here: on Windows the zopen64_file implementation
	/// (MinizipExtensions.cpp) treats the filename as a wide string and opens it with
	/// _wfopen, so callers must pass boost::filesystem::path::c_str(); on other
	/// platforms it is a plain char path. Passing std::string::c_str() would be
	/// interpreted as a wide string, garbling the path so it can never be opened.
	EncryptedZipReader(const zlib_filefunc64_def & fileApi, const void * archivePath,
	                   std::uint64_t centralDirectoryOffset);
	~EncryptedZipReader();

	/// Reads the decrypted data; returns the number of bytes actually read, 0 for end of data, -1 for error
	si64 read(ui8 * data, si64 size);

	bool isFailed() const { return failed; }

private:
	enum class Cipher
	{
		ZipCrypto,
		Aes,
	};

	bool openEntry(std::uint64_t centralDirectoryOffset);
	bool parseAesExtraField(const std::uint8_t * data, std::size_t length);
	bool seek(std::uint64_t offset);
	bool readExact(std::uint8_t * data, std::size_t length);
	bool seekAndRead(std::uint64_t offset, std::uint8_t * data, std::size_t length);
	bool precheckAuthentication(const std::uint8_t * authenticationKey, std::size_t keyLength,
	                            std::uint64_t cipherOffset);
	bool fillPlainBuffer();
	bool inflateChunk(const std::uint8_t * data, std::size_t length);
	void decryptChunk(std::uint8_t * data, std::size_t length);
	void finishEntry();

	/// Stored by value: the caller's instance may be a temporary on the stack
	zlib_filefunc64_def fileApi{};
	voidpf stream = nullptr;

	bool failed = false;
	bool finished = false;

	Cipher cipher = Cipher::Aes;

	/// ZipCrypto: key state computed by the protected bytecode
	ZipCryptoKeys zipCryptoKeys;

	/// AES: strength and streaming decryption state
	ZipAes::Strength aesStrength = ZipAes::Strength::Aes256;
	ZipAes::AesCtrContext aesCtr;
	ZipAes::HmacSha1Context aesHmac;

	/// Compression method actually used for the decrypted data (AES records it in the extra field)
	int compressionMethod = 0;

	std::uint64_t remainingCipher = 0;

	std::vector<ui8> plainBuffer;
	std::size_t plainOffset = 0;

	z_stream inflateStream{};
	bool inflateActive = false;
};

}

VCMI_LIB_NAMESPACE_END
