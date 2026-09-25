/*
 * ZipAesReader.h, part of VCMI engine
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

// 与 MinizipExtensions.h 保持一致：优先用 minizip-ng，其次用传统 minizip。
// 这里只用到它的 IO 回调类型，不使用它的条目读取接口（原因见下面类的说明）。
#if __has_include(<minizip-ng/unzip.h>)
#include <minizip-ng/unzip.h>
#else
#include <minizip/unzip.h>
#endif

VCMI_LIB_NAMESPACE_BEGIN

namespace ZipAes
{

/// 读取 WinZip AES 加密的 zip 条目。
///
/// 为什么不用 minizip 的读取接口：AES 条目的 compression method 是 99，
/// 而 minizip 只认 0 / 8 / 12，即使以 raw 模式打开也会返回 UNZ_BADZIPFILE。
/// 各平台用的都是预先构建好的依赖包，给 minizip 打补丁并不现实。
/// 所以这里只借用它的 IO 回调，自己走一遍 zip 结构：从中央目录项找到本地头，
/// 跳过文件名和 extra field，就得到「salt + 密码校验值 + 密文 + 认证码」。
class ZipAesReader
{
public:
	/// centralDirectoryOffset 取自 unzGetFilePos64() 返回的 pos_in_zip_directory
	ZipAesReader(const zlib_filefunc64_def & fileApi, const std::string & archivePath,
	             std::uint64_t centralDirectoryOffset, const std::string & password);
	~ZipAesReader();

	/// 读取解密后的数据；返回实际读到的字节数，0 表示已读完，-1 表示出错
	si64 read(ui8 * data, si64 size);

	bool isFailed() const { return failed; }

	/// 认证码是否通过校验。只有把整个条目读完才会有结果。
	bool isAuthenticationValid() const { return authenticationValid; }

private:
	bool parseExtraField(const std::uint8_t * data, std::size_t length);
	bool seek(std::uint64_t offset);
	bool readExact(std::uint8_t * data, std::size_t length);
	bool seekAndRead(std::uint64_t offset, std::uint8_t * data, std::size_t length);
	bool fillPlainBuffer();
	bool inflateChunk(const std::uint8_t * data, std::size_t length);
	void finishEntry();

	/// 按值保存：调用方传进来的那一份可能是栈上的临时变量
	zlib_filefunc64_def fileApi{};
	voidpf stream = nullptr;

	bool failed = false;
	bool finished = false;
	bool authenticationValid = false;

	Strength strength = Strength::Aes256;
	int realMethod = 0;

	AesKeyMaterial keyMaterial;
	AesCtrContext cipher;
	HmacSha1Context hmac;

	std::uint64_t remainingCipher = 0;

	std::vector<ui8> plainBuffer;
	std::size_t plainOffset = 0;

	z_stream inflateStream{};
	bool inflateActive = false;
};

}

VCMI_LIB_NAMESPACE_END
