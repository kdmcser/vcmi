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

/// Internal state of ZipCrypto (PKWARE traditional encryption).
///
/// Mirrors the init_keys / decrypt_byte scheme from minizip: three 32-bit keys,
/// where each decrypted byte is first XORed with the key stream and the resulting
/// plaintext byte is then fed back into the key state.
///
/// This is implemented here instead of handing the password over to minizip so that the
/// key state is computed directly from the protected bytecode -- the plaintext password
/// never has to land in any buffer or pass through any "receive password" interface.
struct ZipCryptoKeys
{
	std::uint32_t key0 = 0x12345678;
	std::uint32_t key1 = 0x23456789;
	std::uint32_t key2 = 0x34567890;
};

/// Reset to the initial constants (equivalent to "no password fed yet")
void zipCryptoReset(ZipCryptoKeys & keys);

/// Feed a password byte into the key state
void zipCryptoFeedPassword(ZipCryptoKeys & keys, std::uint8_t passwordByte);

/// Decrypt a single byte and advance the key state
std::uint8_t zipCryptoDecryptByte(ZipCryptoKeys & keys, std::uint8_t cipherByte);

}

VCMI_LIB_NAMESPACE_END
