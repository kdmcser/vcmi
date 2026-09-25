/*
 * ZipAesCrypto.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "ZipAesCrypto.h"

#include <openssl/evp.h>

#include <cstring>

VCMI_LIB_NAMESPACE_BEGIN

namespace ZipAes
{

namespace
{

constexpr std::size_t blockSize = 16;
constexpr std::size_t sha1DigestLength = 20;
constexpr std::size_t sha1BlockLength = 64;

/// The counter used by CTR is a 128-bit little-endian integer
void incrementCounter(std::uint8_t counter[blockSize])
{
	for(int i = 0; i < 16; ++i)
	{
		if(++counter[i] != 0)
			break;
	}
}

}

// ---------------------------------------------------------------------------
// SHA-1: use OpenSSL directly (see the note in the header)
// ---------------------------------------------------------------------------

void sha1Init(Sha1Context & context)
{
	SHA1_Init(&context.handle);
}

void sha1Update(Sha1Context & context, const void * data, std::size_t length)
{
	SHA1_Update(&context.handle, data, length);
}

void sha1Final(Sha1Context & context, std::uint8_t digest[sha1DigestLength])
{
	SHA1_Final(digest, &context.handle);
	secureErase(&context, sizeof(context));
}

// ---------------------------------------------------------------------------
// HMAC-SHA1
// ---------------------------------------------------------------------------

namespace
{

/// XOR the password bytes into the two pad blocks required by HMAC
struct PadFiller
{
	std::uint8_t * innerPad = nullptr;
	std::uint8_t * outerPad = nullptr;
	std::size_t index = 0;
	bool tooLong = false;
};

void fillPadBlock(void * context, std::uint8_t value)
{
	auto * filler = static_cast<PadFiller *>(context);

	if(filler->index < sha1BlockLength)
	{
		filler->innerPad[filler->index] ^= value;
		filler->outerPad[filler->index] ^= value;
	}
	else
	{
		// The password is longer than one SHA-1 block: the spec requires hashing the password with SHA-1 first
		filler->tooLong = true;
	}

	++filler->index;
}

void hashPasswordByte(void * context, std::uint8_t value)
{
	sha1Update(*static_cast<Sha1Context *>(context), &value, 1);
}

bool replayMemoryPassword(void * context, PasswordByteConsumer consumer, void * consumerContext)
{
	auto * password = static_cast<MemoryPassword *>(context);

	for(std::size_t i = 0; i < password->length; ++i)
		consumer(consumerContext, password->bytes[i]);

	return true;
}

}

PasswordByteSource passwordSourceOf(MemoryPassword & password)
{
	PasswordByteSource source;
	source.context = &password;
	source.replay = &replayMemoryPassword;
	return source;
}

bool hmacSha1Prepare(HmacSha1KeySchedule & schedule, const PasswordByteSource & password)
{
	// Start from the pad values and XOR the password bytes in, without going through the step of first assembling a complete password
	std::uint8_t innerPad[sha1BlockLength];
	std::uint8_t outerPad[sha1BlockLength];
	std::memset(innerPad, 0x36, sizeof(innerPad));
	std::memset(outerPad, 0x5c, sizeof(outerPad));

	PadFiller filler;
	filler.innerPad = innerPad;
	filler.outerPad = outerPad;

	const bool replayed = password.replay != nullptr
	                   && password.replay(password.context, &fillPadBlock, &filler);

	if(!replayed)
	{
		secureErase(innerPad, sizeof(innerPad));
		secureErase(outerPad, sizeof(outerPad));
		return false;
	}

	if(filler.tooLong)
	{
		Sha1Context hasher;
		sha1Init(hasher);
		password.replay(password.context, &hashPasswordByte, &hasher);

		std::uint8_t hashedKey[sha1DigestLength];
		sha1Final(hasher, hashedKey);

		std::memset(innerPad, 0x36, sizeof(innerPad));
		std::memset(outerPad, 0x5c, sizeof(outerPad));

		for(std::size_t i = 0; i < sha1DigestLength; ++i)
		{
			innerPad[i] ^= hashedKey[i];
			outerPad[i] ^= hashedKey[i];
		}

		secureErase(hashedKey, sizeof(hashedKey));
	}

	// The SHA-1 state after absorbing the key block is the key schedule shared by all iterations
	sha1Init(schedule.inner);
	sha1Update(schedule.inner, innerPad, sha1BlockLength);

	sha1Init(schedule.outer);
	sha1Update(schedule.outer, outerPad, sha1BlockLength);

	secureErase(innerPad, sizeof(innerPad));
	secureErase(outerPad, sizeof(outerPad));
	return true;
}

void hmacSha1Begin(const HmacSha1KeySchedule & schedule, HmacSha1Context & context)
{
	context.inner = schedule.inner;
	context.outer = schedule.outer;
}

void hmacSha1Init(HmacSha1Context & context, const PasswordByteSource & password)
{
	HmacSha1KeySchedule schedule;
	if(!hmacSha1Prepare(schedule, password))
	{
		// If the source is invalid, finish with an empty password: the derived key will be wrong and
		// decryption will inevitably fail, so a corrupted payload is never silently accepted
		MemoryPassword emptyPassword;
		hmacSha1Prepare(schedule, passwordSourceOf(emptyPassword));
	}

	hmacSha1Begin(schedule, context);
	secureErase(&schedule, sizeof(schedule));
}

void hmacSha1Init(HmacSha1Context & context, const std::uint8_t * key, std::size_t keyLength)
{
	MemoryPassword password;
	password.bytes = key;
	password.length = keyLength;

	hmacSha1Init(context, passwordSourceOf(password));
}

void hmacSha1Update(HmacSha1Context & context, const void * data, std::size_t length)
{
	sha1Update(context.inner, data, length);
}

void hmacSha1Final(HmacSha1Context & context, std::uint8_t digest[sha1DigestLength])
{
	std::uint8_t innerDigest[sha1DigestLength];
	sha1Final(context.inner, innerDigest);
	sha1Update(context.outer, innerDigest, sizeof(innerDigest));
	sha1Final(context.outer, digest);
	secureErase(innerDigest, sizeof(innerDigest));
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA1
// ---------------------------------------------------------------------------

void pbkdf2Sha1(const PasswordByteSource & password,
                const std::uint8_t * salt, std::size_t saltLength,
                std::uint32_t iterations, std::uint8_t * output, std::size_t outputLength)
{
	// A WinZip AES salt is at most 16 bytes; leave ample headroom here and perform a bounds check
	constexpr std::size_t maxSaltLength = 64;

	if(iterations == 0 || saltLength > maxSaltLength)
		return;

	std::uint8_t saltBlock[maxSaltLength + 4];
	std::memcpy(saltBlock, salt, saltLength);

	// The key schedule is built only once. All output blocks and all iterations use the same HMAC key
	// block, so the password is read only once here and the subsequent iterations reuse the SHA-1 state
	// after absorbing the pad directly -- previously the password had to be replayed on every iteration,
	// and the read side paid that cost for every entry it opened.
	HmacSha1KeySchedule schedule;
	if(!hmacSha1Prepare(schedule, password))
	{
		// Password source invalid: zero the output; the caller will reject this entry because the verify value does not match
		std::memset(output, 0, outputLength);
		secureErase(&schedule, sizeof(schedule));
		secureErase(saltBlock, sizeof(saltBlock));
		return;
	}

	std::size_t produced = 0;
	std::uint32_t blockIndex = 1;

	while(produced < outputLength)
	{
		saltBlock[saltLength + 0] = static_cast<std::uint8_t>((blockIndex >> 24) & 0xff);
		saltBlock[saltLength + 1] = static_cast<std::uint8_t>((blockIndex >> 16) & 0xff);
		saltBlock[saltLength + 2] = static_cast<std::uint8_t>((blockIndex >> 8) & 0xff);
		saltBlock[saltLength + 3] = static_cast<std::uint8_t>(blockIndex & 0xff);

		std::uint8_t current[sha1DigestLength];
		std::uint8_t accumulated[sha1DigestLength];

		HmacSha1Context hmac;
		hmacSha1Begin(schedule, hmac);
		hmacSha1Update(hmac, saltBlock, saltLength + 4);
		hmacSha1Final(hmac, current);

		std::memcpy(accumulated, current, sha1DigestLength);

		for(std::uint32_t iteration = 1; iteration < iterations; ++iteration)
		{
			hmacSha1Begin(schedule, hmac);
			hmacSha1Update(hmac, current, sha1DigestLength);
			hmacSha1Final(hmac, current);

			for(std::size_t i = 0; i < sha1DigestLength; ++i)
				accumulated[i] ^= current[i];
		}

		const std::size_t take = std::min(sha1DigestLength, outputLength - produced);
		std::memcpy(output + produced, accumulated, take);
		produced += take;
		++blockIndex;

		secureErase(&hmac, sizeof(hmac));
		secureErase(current, sizeof(current));
		secureErase(accumulated, sizeof(accumulated));
	}

	secureErase(&schedule, sizeof(schedule));
	secureErase(saltBlock, sizeof(saltBlock));
}

void pbkdf2Sha1(const std::uint8_t * password, std::size_t passwordLength,
                const std::uint8_t * salt, std::size_t saltLength,
                std::uint32_t iterations, std::uint8_t * output, std::size_t outputLength)
{
	MemoryPassword memoryPassword;
	memoryPassword.bytes = password;
	memoryPassword.length = passwordLength;

	pbkdf2Sha1(passwordSourceOf(memoryPassword), salt, saltLength, iterations, output, outputLength);
}

// ---------------------------------------------------------------------------
// AES: the keystream is generated in bulk with EVP (using AES-NI)
// ---------------------------------------------------------------------------

void aesCtrInit(AesCtrContext & context, Strength strength, const std::uint8_t * key)
{
	context.strength = strength;
	std::memcpy(context.key, key, keyLength(strength));

	std::memset(context.counter, 0, sizeof(context.counter));
	context.counter[0] = 1;

	context.streamUsed = keystreamBytes; // marks the pool as empty; it is generated on first use
}

namespace
{

/// Generate an entire pool of keystream in one batch.
///
/// The CTR keystream is simply AES encryption of the counter blocks. WinZip's counter is a 128-bit
/// little-endian integer starting at 1, so the counters for consecutive blocks are 1, 2, 3, ... Once
/// filled in, they are handed to EVP for a single bulk ECB encryption. A single-block call to the
/// low-level AES_encrypt reaches only 247 MB/s (it goes through the generic C implementation), whereas
/// EVP in bulk reaches 11 GB/s.
void refillKeystream(AesCtrContext & context)
{
	for(std::size_t block = 0; block < keystreamBlocks; ++block)
	{
		std::memcpy(context.stream + block * blockSize, context.counter, blockSize);
		incrementCounter(context.counter);
	}

	const EVP_CIPHER * algorithm = context.strength == Strength::Aes128 ? EVP_aes_128_ecb()
	                            : context.strength == Strength::Aes192 ? EVP_aes_192_ecb()
	                            : EVP_aes_256_ecb();

	EVP_CIPHER_CTX * cipher = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(cipher, algorithm, nullptr, context.key, nullptr);
	EVP_CIPHER_CTX_set_padding(cipher, 0);

	int outLength = 0;
	EVP_EncryptUpdate(cipher, context.stream, &outLength, context.stream, static_cast<int>(keystreamBytes));

	EVP_CIPHER_CTX_free(cipher);
	context.streamUsed = 0;
}

}

void aesCtrCrypt(AesCtrContext & context, std::uint8_t * data, std::size_t length)
{
	std::size_t i = 0;

	while(i < length)
	{
		if(context.streamUsed == keystreamBytes)
			refillKeystream(context);

		const std::size_t available = keystreamBytes - context.streamUsed;
		const std::size_t take = length - i < available ? length - i : available;

		const std::uint8_t * stream = context.stream + context.streamUsed;
		for(std::size_t k = 0; k < take; ++k)
			data[i + k] ^= stream[k];

		i += take;
		context.streamUsed += take;
	}
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

void deriveAesKeys(Strength strength, const PasswordByteSource & password,
                   const std::uint8_t * salt, AesKeyMaterial & keys)
{
	const std::size_t length = keyLength(strength);

	// A single PBKDF2 call produces (2 * key length + 2) bytes, which are then split in the order specified by the spec
	std::uint8_t derived[2 * 32 + 2];

	pbkdf2Sha1(password, salt, saltLength(strength), pbkdf2Iterations,
	           derived, 2 * length + verifyValueLength);

	std::memcpy(keys.encryptionKey, derived, length);
	std::memcpy(keys.authenticationKey, derived + length, length);
	std::memcpy(keys.verifyValue, derived + 2 * length, verifyValueLength);

	secureErase(derived, sizeof(derived));
}

void secureErase(void * data, std::size_t length)
{
	// Write in 8-byte groups, still volatile (so the compiler likewise cannot optimize it away), just with
	// fewer stores. SHA-1 wipes a 320-byte schedule for every block, and PBKDF2 runs thousands of blocks
	// per entry, so byte-by-byte writes are a noticeable cost here.
	std::uint8_t * raw = static_cast<std::uint8_t *>(data);

	while(length > 0 && (reinterpret_cast<std::uintptr_t>(raw) & 7u) != 0)
	{
		*reinterpret_cast<volatile std::uint8_t *>(raw) = 0;
		++raw;
		--length;
	}

	while(length >= 8)
	{
		*reinterpret_cast<volatile std::uint64_t *>(raw) = 0;
		raw += 8;
		length -= 8;
	}

	while(length > 0)
	{
		*reinterpret_cast<volatile std::uint8_t *>(raw) = 0;
		++raw;
		--length;
	}
}

}

VCMI_LIB_NAMESPACE_END
