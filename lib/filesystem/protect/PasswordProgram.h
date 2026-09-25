/*
 * PasswordProgram.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include "StdInc.h"
#include "ZipCrypto.h"

#include <string>

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{

/// 密码字节的消费者，每拿到一个字节调用一次
using PasswordByteConsumer = void (*)(void * context, std::uint8_t value);

/// 运行密码还原字节码，把每个密码字节交给 consumer。
///
/// 没有「返回完整密码」的接口：密码只在 VM 内部逐字节流转，调用方拿到的
/// 也只是一个个字节。AES 的密钥派生每次重建 HMAC 密钥块都会重放一遍。
/// 返回 false 表示字节码执行失败，此时交出去的字节不可信。
bool derivePasswordBytes(PasswordByteConsumer consumer, void * context);

/// 直接算出 ZipCrypto 的密钥状态。密码明文只在 VM 内部逐字节流转，
/// 既不会被拼成完整字符串，也不经过任何"接收密码"的接口。
void deriveZipCryptoKeys(ZipCryptoKeys & keys);

}

VCMI_LIB_NAMESPACE_END
