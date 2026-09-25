/*
 * ZipAesCrypto.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include "StdInc.h"

VCMI_LIB_NAMESPACE_BEGIN

/// WinZip AES（AE-1 / AE-2）解密所需的密码学原语。
///
/// 为什么自带一份而不是直接用 OpenSSL：各平台的依赖包里未必都有 OpenSSL。
/// 例如 Apple 平台（iOS / macOS），VCMI 依赖图里的 OpenSSL 是跟着 Qt 的 openssl 选项
/// 进来的，而那个选项在 Apple 平台是关掉的（改用系统 SecureTransport），
/// 所以 iOS / macOS 的依赖包里没有 OpenSSL。
/// 自带实现可以保证同一套代码在 Windows / Android / iOS / macOS 上都能编译，
/// 也不需要改动 dependencies/conanfile.py 重新构建依赖包。
namespace ZipAes
{

/// WinZip AES 的三档强度，数值与 extra field 0x9901 里的 strength 字段一致
enum class Strength : std::uint8_t
{
	Aes128 = 1,
	Aes192 = 2,
	Aes256 = 3,
};

/// 三档强度各自对应的密钥长度
constexpr std::size_t keyLength(Strength strength)
{
	return strength == Strength::Aes128 ? 16
	     : strength == Strength::Aes192 ? 24
	     : 32;
}

/// 三档强度各自对应的 salt 长度
constexpr std::size_t saltLength(Strength strength)
{
	return strength == Strength::Aes128 ? 8
	     : strength == Strength::Aes192 ? 12
	     : 16;
}

/// 密码校验值和认证码的长度，三档强度都一样
constexpr std::size_t verifyValueLength = 2;
constexpr std::size_t authCodeLength = 10;

/// 规范规定的 PBKDF2 迭代次数
constexpr std::uint32_t pbkdf2Iterations = 1000;

// ---------------------------------------------------------------------------
// SHA-1（FIPS 180-1），支持增量更新
// ---------------------------------------------------------------------------

struct Sha1Context
{
	std::uint32_t state[5];
	std::uint64_t totalLength;
	std::uint8_t buffer[64];
	std::size_t bufferedLength;
};

void sha1Init(Sha1Context & context);
void sha1Update(Sha1Context & context, const void * data, std::size_t length);
void sha1Final(Sha1Context & context, std::uint8_t digest[20]);

// ---------------------------------------------------------------------------
// HMAC-SHA1（RFC 2104），支持增量更新
// ---------------------------------------------------------------------------

struct HmacSha1Context
{
	Sha1Context inner;
	Sha1Context outer;
};

/// 密码字节的消费者，每拿到一个字节调用一次
using PasswordByteConsumer = void (*)(void * context, std::uint8_t value);

/// 能反复从头提供密码字节的来源。
///
/// 为什么不用「指针 + 长度」：那样调用方手里得先有一份完整的密码原文，而
/// PBKDF2 会反复重建 HMAC 的密钥块，这份原文就得在整个派生期间一直留着，
/// 谁都能一次读走。改成按需重放之后，密码只在需要它的那一刻逐字节出现。
struct PasswordByteSource
{
	void * context = nullptr;

	/// 把密码字节依次交给 consumer；返回 false 表示来源失效（此时密码不可信）
	bool (*replay)(void * context, PasswordByteConsumer consumer, void * consumerContext) = nullptr;
};

/// 用一段现成的密码缓冲区当来源，供测试向量之类的调用方使用。
/// password 的生命周期由调用方保证。
struct MemoryPassword
{
	const std::uint8_t * bytes = nullptr;
	std::size_t length = 0;
};

PasswordByteSource passwordSourceOf(MemoryPassword & password);

void hmacSha1Init(HmacSha1Context & context, const PasswordByteSource & password);
void hmacSha1Init(HmacSha1Context & context, const std::uint8_t * key, std::size_t keyLength);
void hmacSha1Update(HmacSha1Context & context, const void * data, std::size_t length);
void hmacSha1Final(HmacSha1Context & context, std::uint8_t digest[20]);

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA1（RFC 2898）
// ---------------------------------------------------------------------------

void pbkdf2Sha1(const PasswordByteSource & password,
                const std::uint8_t * salt, std::size_t saltLength,
                std::uint32_t iterations, std::uint8_t * output, std::size_t outputLength);

void pbkdf2Sha1(const std::uint8_t * password, std::size_t passwordLength,
                const std::uint8_t * salt, std::size_t saltLength,
                std::uint32_t iterations, std::uint8_t * output, std::size_t outputLength);

// ---------------------------------------------------------------------------
// AES：只做加密方向，因为 CTR 模式的解密用的也是加密方向
// ---------------------------------------------------------------------------

/// 轮密钥最多 60 个字：AES-256 需要 4 * (14 + 1) = 60
struct AesContext
{
	std::uint32_t roundKeys[60];
	int rounds;
};

void aesInit(AesContext & context, Strength strength, const std::uint8_t * key);
void aesEncryptBlock(const AesContext & context, const std::uint8_t input[16], std::uint8_t output[16]);

/// WinZip AES 用的 CTR 流。
/// 要点：16 字节计数器按 128 位「小端」整数处理，初值为 1 —— 这是实现里最容易写错的地方。
struct AesCtrContext
{
	AesContext cipher;
	std::uint8_t counter[16];
	std::uint8_t stream[16];
	std::size_t streamUsed;
};

void aesCtrInit(AesCtrContext & context, Strength strength, const std::uint8_t * key);
void aesCtrCrypt(AesCtrContext & context, std::uint8_t * data, std::size_t length);

// ---------------------------------------------------------------------------
// WinZip AES 的密钥材料
// ---------------------------------------------------------------------------

/// 规范要求一次 PBKDF2 派生 (2 * 密钥长度 + 2) 字节，
/// 按顺序切成加密密钥、HMAC 密钥和 2 字节的密码校验值
struct AesKeyMaterial
{
	std::uint8_t encryptionKey[32];
	std::uint8_t authenticationKey[32];
	std::uint8_t verifyValue[2];
};

void deriveAesKeys(Strength strength, const PasswordByteSource & password,
                   const std::uint8_t * salt, AesKeyMaterial & keys);

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

/// 擦除内存中的敏感数据。用 volatile 写，避免被编译器当作无用赋值优化掉。
void secureErase(void * data, std::size_t length);

}

VCMI_LIB_NAMESPACE_END
