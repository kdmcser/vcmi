/*
 * SecretConstants.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include "StdInc.h"

#include <cstddef>
#include <cstdint>
#include <string>

VCMI_LIB_NAMESPACE_BEGIN

/// mod 密码的还原。
///
/// 密文与掩码都不以原样形式出现在二进制里：材料由 CMake 在配置阶段拆成交错碎片
/// 写入构建目录的头文件（cmake/ModPasswordSecrets.cmake），密文片里存的是
/// base64 字母表下标，掩码片里存的是异或过的值，每片各自的键随构建目录随机生成。
/// 想拿到原始材料必须读懂这里的还原逻辑，再把那些键从二进制里找出来。
namespace ModPassword
{

/// 还原密码密文（base64 形式）
std::string secretCipher();

/// 还原掩码第 index 个字节（碎片里存的是异或过的值）
std::uint8_t secretMaskByte(std::size_t index);

/// 掩码字节数
std::size_t secretMaskLength();

}

VCMI_LIB_NAMESPACE_END
