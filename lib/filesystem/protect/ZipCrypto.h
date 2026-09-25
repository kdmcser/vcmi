/*
 * ZipCrypto.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include "StdInc.h"

#include <cstdint>

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{

/// ZipCrypto（PKWARE 传统加密）的内部状态。
///
/// 对应 minizip 里 init_keys / decrypt_byte 那套算法：三个 32 位密钥，
/// 每解一个字节先用密钥流异或，再用得到的明文回填密钥状态。
///
/// 这里自己实现而不是把密码交给 minizip，是为了让密钥状态由受保护的字节码
/// 直接算出来 —— 密码明文不必落进任何缓冲区、也不经过任何"接收密码"的接口。
struct ZipCryptoKeys
{
	std::uint32_t key0 = 0x12345678;
	std::uint32_t key1 = 0x23456789;
	std::uint32_t key2 = 0x34567890;
};

/// 复位到初始常量（等价于"还没喂过密码"）
void zipCryptoReset(ZipCryptoKeys & keys);

/// 把一个密码字节喂进密钥表
void zipCryptoFeedPassword(ZipCryptoKeys & keys, std::uint8_t passwordByte);

/// 解密一个字节并推进密钥状态
std::uint8_t zipCryptoDecryptByte(ZipCryptoKeys & keys, std::uint8_t cipherByte);

}

VCMI_LIB_NAMESPACE_END
