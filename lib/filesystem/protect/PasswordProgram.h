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

/// 还原 mod 密码明文。AES 的密钥派生需要密码原文，所以这条路无法避免
/// 明文短暂存在 —— 调用方拿到后应立刻使用并擦除。
///
/// 与 modpack-tool 侧的实现相比，这里去掉了授权门与字节码自校验：
/// VCMI 只是读取方，没有"未注册"的概念，篡改字节码也换不到额外收益，
/// 加了只会白白增加复杂度和体积。
std::string derivePassword();

/// 直接算出 ZipCrypto 的密钥状态。密码明文只在 VM 内部逐字节流转，
/// 既不会被拼成完整字符串，也不经过任何"接收密码"的接口。
void deriveZipCryptoKeys(ZipCryptoKeys & keys);

/// 擦掉字符串里的敏感内容（用 volatile 写，避免被编译器优化掉）
void eraseSecret(std::string & text);

}

VCMI_LIB_NAMESPACE_END
