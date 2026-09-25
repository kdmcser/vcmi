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

/// 各掩码碎片在生成时异或过的常量，必须与 cmake/ModPasswordSecrets.cmake 保持一致
constexpr std::uint8_t shardKeys[Secrets::maskShardCount] = { 0x71, 0x1E, 0x9B, 0x44 };

/// volatile 读取，避免编译器把碎片重新拼成一份连续的常量放进二进制
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
		const volatile char * data = Secrets::cipherShard[shard];
		result[i] = data[offset];
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

	const volatile std::uint8_t * data = maskShardData(shard);
	return static_cast<std::uint8_t>(data[offset] ^ shardKeys[shard]);
}

std::size_t secretMaskLength()
{
	return Secrets::maskLength;
}

}

VCMI_LIB_NAMESPACE_END
