/*
 * AntiDebug.h, part of VCMI engine
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

/// 调试器检测，只服务于受保护逻辑内部。
///
/// 检测结果不通过返回值暴露「是否被调试」，而是换算成一个偏置字节叠进掩码：
/// 命中时还原出来的密码是错的，解密自然失败。不弹窗、不报错，也不留一个
/// 可以改成 true 的布尔判断 —— 与 maskBias() 是同一套思路。
///
/// 检测范围只限「有没有调试器附加到本进程」，外加单步执行的定时特征：
///
/// - 不查硬件断点：RTSS 一类的叠加层会在目标进程里下硬件断点，查了会误伤
/// - 不拦 DLL 注入、不枚举窗口、不做虚拟机识别、不碰内存保护
///
/// 因此录屏与叠加层工具（OBS 游戏捕获、Afterburner、Discord/Steam overlay）
/// 正常工作，它们靠注入钩子渲染，不是调试器。
///
/// 生效范围由构建配置决定，不需要手工干预：
///
/// - Release            -> 编入（发布用）
/// - Debug / RelWithDebInfo -> 编译成空，留给本地带调试器工作
///
/// 判定放在 CMake 侧（lib/CMakeLists.txt 里按 $<CONFIG:Release> 传
/// MODPASSWORD_ANTIDEBUG）而不是代码里的 NDEBUG：Release 与 RelWithDebInfo
/// 都会定义 NDEBUG，用预处理器区分不开这两者。
///
/// 需要特意构造"带保护但不带反调试"的对照构建（例如比对杀软误报增量）时，
/// 定义 MODPASSWORD_NO_ANTIDEBUG 可在任意配置下强制关闭。
std::uint8_t antiDebugBias();

}

VCMI_LIB_NAMESPACE_END
