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
/// 密文与掩码都不以连续形式出现在二进制里：它们由 CMake 在配置阶段拆成交错碎片
/// 写入构建目录的头文件（cmake/ModPasswordSecrets.cmake），掩码的每一片还各自
/// 异或过一个常量。想拿到原始材料必须读懂这里的还原逻辑。
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
