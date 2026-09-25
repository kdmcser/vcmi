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

/// Consumer of password bytes, invoked once for every byte received
using PasswordByteConsumer = void (*)(void * context, std::uint8_t value);

/// Runs the password recovery bytecode, feeding every password byte to consumer.
///
/// There is no interface that "returns the full password": the password only flows
/// byte by byte inside the VM, and the caller likewise receives nothing but single
/// bytes. AES key derivation replays it every time the HMAC key block is rebuilt.
/// Returning false means the bytecode failed to execute, in which case the bytes
/// handed out are not trustworthy.
bool derivePasswordBytes(PasswordByteConsumer consumer, void * context);

/// Computes the ZipCrypto key state directly. The plaintext password only flows byte
/// by byte inside the VM; it is never assembled into a complete string, nor does it
/// pass through any "receive password" interface.
void deriveZipCryptoKeys(ZipCryptoKeys & keys);

}

VCMI_LIB_NAMESPACE_END
