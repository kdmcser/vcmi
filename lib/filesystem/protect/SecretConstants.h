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

/// Reconstruction of the mod password.
///
/// Neither the ciphertext nor the mask appears verbatim in the binary: CMake splits the
/// material into interleaved shards at configure time and writes them to a header in the
/// build directory (cmake/ModPasswordSecrets.cmake). The ciphertext shards store base64
/// alphabet indices, the mask shards store XOR-obfuscated values, and each shard's key is
/// randomly generated per build directory. Recovering the original material requires
/// understanding the reconstruction logic here and then locating those keys in the binary.
namespace ModPassword
{

/// Reconstruct the password ciphertext (base64 form)
std::string secretCipher();

/// Reconstruct the index-th mask byte (the shard stores an XOR-obfuscated value)
std::uint8_t secretMaskByte(std::size_t index);

/// Mask length in bytes
std::size_t secretMaskLength();

}

VCMI_LIB_NAMESPACE_END
