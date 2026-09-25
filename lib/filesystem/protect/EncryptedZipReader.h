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
#include "ZipAesCrypto.h"
#include "ZipCrypto.h"

#include <vector>

// 与 MinizipExtensions.h 保持一致：优先用 minizip-ng，其次用传统 minizip。
// 这里只用到它的 IO 回调类型，不使用它的条目读取接口。
#if __has_include(<minizip-ng/unzip.h>)
#include <minizip-ng/unzip.h>
#else
#include <minizip/unzip.h>
#endif

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{

/// 读取加密的 zip 条目，ZipCrypto 与 WinZip AES 两种都支持。
///
/// 为什么两种情况都不交给 minizip：
///   * AES 条目的 method 是 99，minizip 只认 0 / 8 / 12，即使以 raw 模式打开
///     也会返回 UNZ_BADZIPFILE；各平台用的是预先构建好的依赖包，给它打补丁不现实。
///   * ZipCrypto 如果交给 minizip，就必须把密码明文传进 unzOpenCurrentFilePassword，
///     而那正是攻击者想要的。这里改成由受保护的字节码直接算出密钥状态，
///     密码明文不落进任何缓冲区。
///
/// 所以自己走一遍 zip 结构：从中央目录项找到本地头，跳过文件名和 extra field，
/// 就得到该条目的加密数据。
class EncryptedZipReader
{
public:
	/// centralDirectoryOffset 取自 unzGetFilePos64() 返回的 pos_in_zip_directory
	EncryptedZipReader(const zlib_filefunc64_def & fileApi, const std::string & archivePath,
	                   std::uint64_t centralDirectoryOffset);
	~EncryptedZipReader();

	/// 读取解密后的数据；返回实际读到的字节数，0 表示已读完，-1 表示出错
	si64 read(ui8 * data, si64 size);

	bool isFailed() const { return failed; }

	/// 该条目是否带认证码（只有 AES 有，ZipCrypto 没有）
	bool hasAuthenticationCode() const { return cipher == Cipher::Aes; }

	/// AES 的认证码是否通过校验（ZipCrypto 没有认证码，恒为 false）
	bool isAuthenticationValid() const { return authenticationValid; }

	/// 调用方读完条目后调用：数据已全部读完时，把末尾的认证码校验掉。
	/// 认证码在数据末尾，没读完就无从校验，这种情况直接放弃（不是失败）。
	void finishEntryIfComplete();

	/// 认证码是否「已校验且未通过」——说明密文被改过或损坏。
	/// 没读完的条目、以及没有认证码的 ZipCrypto 条目恒为 false
	bool isAuthenticationFailed() const { return authenticationChecked && !authenticationValid; }

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
	bool fillPlainBuffer();
	bool inflateChunk(const std::uint8_t * data, std::size_t length);
	void decryptChunk(std::uint8_t * data, std::size_t length);
	void finishEntry();

	/// 按值保存：调用方传进来的那一份可能是栈上的临时变量
	zlib_filefunc64_def fileApi{};
	voidpf stream = nullptr;

	bool failed = false;
	bool finished = false;
	bool authenticationValid = false;

	/// 认证码是否真的被读过并比对过。false 表示无法校验（没读完 / 无认证码），
	/// 这时 authenticationValid 的值没有意义
	bool authenticationChecked = false;

	Cipher cipher = Cipher::Aes;

	/// ZipCrypto：由受保护的字节码算出来的密钥状态
	ZipCryptoKeys zipCryptoKeys;

	/// AES：强度与流式解密状态
	ZipAes::Strength aesStrength = ZipAes::Strength::Aes256;
	ZipAes::AesCtrContext aesCtr;
	ZipAes::HmacSha1Context aesHmac;

	/// 解密后数据实际使用的压缩方法（AES 把它记在 extra field 里）
	int compressionMethod = 0;

	std::uint64_t remainingCipher = 0;

	std::vector<ui8> plainBuffer;
	std::size_t plainOffset = 0;

	z_stream inflateStream{};
	bool inflateActive = false;
};

}

VCMI_LIB_NAMESPACE_END
