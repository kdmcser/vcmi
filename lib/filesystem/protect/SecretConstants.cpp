/*
 * SecretConstants.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "SecretConstants.h"

#include "secrets.h" // 由 CMake 生成到构建目录，不进版本库

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{

namespace
{

/// 密文碎片里存的是这张表的下标，64 表示填充符 '='
constexpr char base64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// volatile 读取，避免编译器把碎片重新拼成一份连续的常量放进二进制
const volatile std::uint8_t * cipherShardData(std::size_t shard)
{
	switch(shard)
	{
	case 0:
		return Secrets::cipherShard0;
	case 1:
		return Secrets::cipherShard1;
	case 2:
		return Secrets::cipherShard2;
	default:
		return Secrets::cipherShard3;
	}
}

const volatile std::uint8_t * maskShardData(std::size_t shard)
{
	switch(shard)
	{
	case 0:
		return Secrets::maskShard0;
	case 1:
		return Secrets::maskShard1;
	case 2:
		return Secrets::maskShard2;
	default:
		return Secrets::maskShard3;
	}
}

}

std::string secretCipher()
{
	std::string result;
	result.resize(Secrets::cipherLength);

	for(std::size_t i = 0; i < result.size(); ++i)
	{
		const std::size_t shard = i % Secrets::cipherShardCount;
		const std::size_t offset = i / Secrets::cipherShardCount;

		const std::uint8_t value = static_cast<std::uint8_t>(
		    cipherShardData(shard)[offset] ^ Secrets::cipherShardKeys[shard]);

		result[i] = value < 64 ? base64Alphabet[value] : '=';
	}

	return result;
}

std::uint8_t secretMaskByte(std::size_t index)
{
	if(Secrets::maskLength == 0)
		return 0;

	// 与 VCMI 原来的还原方式一致：掩码按长度循环使用，而不是越界后补 0
	const std::size_t wrapped = index % Secrets::maskLength;
	const std::size_t shard = wrapped % Secrets::maskShardCount;
	const std::size_t offset = wrapped / Secrets::maskShardCount;

	const std::uint8_t value = static_cast<std::uint8_t>(
	    maskShardData(shard)[offset] ^ Secrets::maskShardKeys[shard]);

	return value;
}

std::size_t secretMaskLength()
{
	return Secrets::maskLength;
}

}

VCMI_LIB_NAMESPACE_END
