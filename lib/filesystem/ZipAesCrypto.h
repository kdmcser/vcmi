/*
 * ZipAesCrypto.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include "StdInc.h"

// OpenSSL 3.0 marks the low-level SHA1_*/AES_* interfaces as deprecated and recommends EVP. SHA-1 here
// specifically needs the low-level interface (EVP would create a context for every hash, which costs more).
// This macro must be defined before the include.
#ifndef OPENSSL_SUPPRESS_DEPRECATED
#  define OPENSSL_SUPPRESS_DEPRECATED
#endif
#include <openssl/sha.h>

VCMI_LIB_NAMESPACE_BEGIN

/// Cryptographic primitives required for WinZip AES (AE-1 / AE-2) decryption.
///
/// SHA-1 and AES use OpenSSL directly: reading and writing encrypted zips is a CPU-intensive path, and
/// OpenSSL uses the SHA-NI / AES-NI hardware instructions, an order of magnitude faster than a custom
/// implementation (the custom SHA-1 runs at about 200 MB/s and AES at about 59 MB/s, whereas with OpenSSL
/// they reach 2800 MB/s and 3000 MB/s respectively).
namespace ZipAes
{

/// The three strength levels of WinZip AES; the values match the strength field of extra field 0x9901
enum class Strength : std::uint8_t
{
	Aes128 = 1,
	Aes192 = 2,
	Aes256 = 3,
};

/// Key length for each of the three strength levels
constexpr std::size_t keyLength(Strength strength)
{
	return strength == Strength::Aes128 ? 16
	     : strength == Strength::Aes192 ? 24
	     : 32;
}

/// Salt length for each of the three strength levels
constexpr std::size_t saltLength(Strength strength)
{
	return strength == Strength::Aes128 ? 8
	     : strength == Strength::Aes192 ? 12
	     : 16;
}

/// Length of the password verify value and the authentication code; identical for all three strength levels
constexpr std::size_t verifyValueLength = 2;
constexpr std::size_t authCodeLength = 10;

/// PBKDF2 iterations mandated by the specification
constexpr std::uint32_t pbkdf2Iterations = 1000;

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-1), with incremental update support
// ---------------------------------------------------------------------------

/// SHA-1 context (OpenSSL implementation, see the note at the top of the file)
struct Sha1Context
{
	SHA_CTX handle;
};

void sha1Init(Sha1Context & context);
void sha1Update(Sha1Context & context, const void * data, std::size_t length);
void sha1Final(Sha1Context & context, std::uint8_t digest[20]);

// ---------------------------------------------------------------------------
// HMAC-SHA1 (RFC 2104), with incremental update support
// ---------------------------------------------------------------------------

struct HmacSha1Context
{
	Sha1Context inner;
	Sha1Context outer;
};

/// Consumer of password bytes, invoked once for every byte it receives
using PasswordByteConsumer = void (*)(void * context, std::uint8_t value);

/// A source that can repeatedly supply the password bytes from the beginning.
///
/// Why not use a "pointer + length" instead: that would force the caller to already hold a complete
/// plaintext copy of the password, and since PBKDF2 repeatedly rebuilds the HMAC key block, that copy
/// would have to stay around for the whole derivation, where anyone could read it out in one go. With
/// on-demand replay, the password only appears byte by byte at the moment it is needed.
struct PasswordByteSource
{
	void * context = nullptr;

	/// Hand the password bytes to consumer one after another; returning false means the source is invalid (and the password is then untrustworthy)
	bool (*replay)(void * context, PasswordByteConsumer consumer, void * consumerContext) = nullptr;
};

/// Use an existing password buffer as the source, for callers such as test vectors.
/// The lifetime of `password` is guaranteed by the caller.
struct MemoryPassword
{
	const std::uint8_t * bytes = nullptr;
	std::size_t length = 0;
};

PasswordByteSource passwordSourceOf(MemoryPassword & password);

void hmacSha1Init(HmacSha1Context & context, const PasswordByteSource & password);
void hmacSha1Init(HmacSha1Context & context, const std::uint8_t * key, std::size_t keyLength);
void hmacSha1Update(HmacSha1Context & context, const void * data, std::size_t length);
void hmacSha1Final(HmacSha1Context & context, std::uint8_t digest[20]);

/// HMAC key schedule: the intermediate SHA-1 state after absorbing the key block (pad).
///
/// Every PBKDF2 iteration uses the same key block, yet the original code re-read the password and
/// recomputed the pad on every iteration. The read side runs a full PBKDF2 for every encrypted entry it
/// opens (1000 iterations x 4 output blocks), so this overhead gets multiplied thousands of times -- this
/// is the main reason decryption was slow. Storing the state after absorbing the pad and reusing it
/// reduces "a password replay per iteration" to "one per derivation".
///
/// Security: what is stored is the SHA-1 intermediate state after absorbing the pad; it is one-way and
/// cannot be used to recover the password.
struct HmacSha1KeySchedule
{
	Sha1Context inner;
	Sha1Context outer;
};

/// Build the key schedule from the password source (the password is read only once, here). Returns false if the password source is invalid.
bool hmacSha1Prepare(HmacSha1KeySchedule & schedule, const PasswordByteSource & password);

/// Begin an HMAC using an existing key schedule (equivalent to hmacSha1Init, but without reading the password again)
void hmacSha1Begin(const HmacSha1KeySchedule & schedule, HmacSha1Context & context);

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA1 (RFC 2898)
// ---------------------------------------------------------------------------

void pbkdf2Sha1(const PasswordByteSource & password,
                const std::uint8_t * salt, std::size_t saltLength,
                std::uint32_t iterations, std::uint8_t * output, std::size_t outputLength);

void pbkdf2Sha1(const std::uint8_t * password, std::size_t passwordLength,
                const std::uint8_t * salt, std::size_t saltLength,
                std::uint32_t iterations, std::uint8_t * output, std::size_t outputLength);

// ---------------------------------------------------------------------------
// AES: encryption direction only, since CTR-mode decryption also uses the encryption direction
// ---------------------------------------------------------------------------

/// keystream pool size: generate 1024 blocks (16 KB) in one batch to amortize the EVP call overhead
///
/// The keystream is generated in bulk with EVP's AES-ECB: a single-block call to the low-level
/// AES_encrypt measures only 247 MB/s (it goes through the generic C implementation), while EVP in bulk
/// reaches 11 GB/s (via AES-NI).
constexpr std::size_t keystreamBlocks = 1024;
constexpr std::size_t keystreamBytes = keystreamBlocks * 16;

/// The CTR stream used by WinZip AES.
/// Key point: the 16-byte counter is treated as a 128-bit "little-endian" integer with an initial value of 1 -- this is the easiest place to get the implementation wrong.
///
/// Only POD is stored here (key, counter, keystream pool): the caller wipes this structure as a whole,
/// so it must not hold any resource that needs to be released separately.
struct AesCtrContext
{
	Strength strength = Strength::Aes256;
	std::uint8_t key[32] = {};
	std::uint8_t counter[16] = {};
	std::uint8_t stream[keystreamBytes] = {};
	/// Number of keystream bytes already consumed; equal to keystreamBytes means the pool is exhausted
	std::size_t streamUsed = keystreamBytes;
};

void aesCtrInit(AesCtrContext & context, Strength strength, const std::uint8_t * key);
void aesCtrCrypt(AesCtrContext & context, std::uint8_t * data, std::size_t length);

// ---------------------------------------------------------------------------
// WinZip AES key material
// ---------------------------------------------------------------------------

/// The specification requires a single PBKDF2 derivation of (2 * key length + 2) bytes,
/// split in order into the encryption key, the HMAC key and the 2-byte password verify value
struct AesKeyMaterial
{
	std::uint8_t encryptionKey[32];
	std::uint8_t authenticationKey[32];
	std::uint8_t verifyValue[2];
};

void deriveAesKeys(Strength strength, const PasswordByteSource & password,
                   const std::uint8_t * salt, AesKeyMaterial & keys);

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Erase sensitive data from memory. Uses volatile writes so the compiler does not optimize them away as dead stores.
void secureErase(void * data, std::size_t length);

}

VCMI_LIB_NAMESPACE_END
