/*
 * ZipCrypto.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "ZipCrypto.h"

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{

namespace
{

/// CRC32 used by ZipCrypto (reflected polynomial 0xEDB88320)
std::uint32_t crc32Update(std::uint32_t crc, std::uint8_t value)
{
	crc ^= value;
	for(int bit = 0; bit < 8; ++bit)
		crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
	return crc;
}

void updateKeys(ZipCryptoKeys & keys, std::uint8_t plainByte)
{
	keys.key0 = crc32Update(keys.key0, plainByte);
	keys.key1 = keys.key1 + (keys.key0 & 0xff);
	keys.key1 = keys.key1 * 134775813u + 1;
	keys.key2 = crc32Update(keys.key2, static_cast<std::uint8_t>(keys.key1 >> 24));
}

/// Current key stream byte
std::uint8_t keyStreamByte(const ZipCryptoKeys & keys)
{
	const std::uint32_t temp = keys.key2 | 2;
	return static_cast<std::uint8_t>((temp * (temp ^ 1)) >> 8);
}

}

void zipCryptoReset(ZipCryptoKeys & keys)
{
	keys.key0 = 0x12345678;
	keys.key1 = 0x23456789;
	keys.key2 = 0x34567890;
}

void zipCryptoFeedPassword(ZipCryptoKeys & keys, std::uint8_t passwordByte)
{
	updateKeys(keys, passwordByte);
}

std::uint8_t zipCryptoDecryptByte(ZipCryptoKeys & keys, std::uint8_t cipherByte)
{
	const std::uint8_t plainByte = static_cast<std::uint8_t>(cipherByte ^ keyStreamByte(keys));
	updateKeys(keys, plainByte);
	return plainByte;
}

}

VCMI_LIB_NAMESPACE_END
