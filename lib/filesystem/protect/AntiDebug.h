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

/// Debugger detection, serving only internal protected logic.
///
/// The result does not expose "am I being debugged" through a return value; instead
/// it is converted into a bias byte folded into the mask: when triggered, the
/// recovered password is wrong and decryption naturally fails. No dialog, no error,
/// and no boolean check that could be flipped to true -- the same approach as
/// maskBias().
///
/// The detection scope is limited to "is a debugger attached to this process",
/// plus the timing signature of single-stepping:
///
/// - No hardware breakpoint checks: overlay tools such as RTSS set hardware
///   breakpoints in the target process, so checking for them would cause false positives
/// - No DLL injection blocking, no window enumeration, no VM detection, no touching of memory protection
///
/// As a result, screen recording and overlay tools (OBS game capture, Afterburner,
/// Discord/Steam overlay) keep working, since they render by injecting hooks, not
/// by acting as debuggers.
///
/// Whether it is active is decided by the build configuration, with no manual
/// intervention required:
///
/// - Release            -> compiled in (for releases)
/// - Debug / RelWithDebInfo -> compiled out, leaving room for local work under a debugger
///
/// The decision lives on the CMake side (lib/CMakeLists.txt passes
/// MODPASSWORD_ANTIDEBUG based on $<CONFIG:Release>) rather than on NDEBUG in the
/// code: both Release and RelWithDebInfo define NDEBUG, so the preprocessor cannot
/// tell the two apart.
///
/// To deliberately construct a control build that has protection but no anti-debug
/// (for example to compare the delta in antivirus false positives), defining
/// MODPASSWORD_NO_ANTIDEBUG forces it off in any configuration.
std::uint8_t antiDebugBias();

}

VCMI_LIB_NAMESPACE_END
