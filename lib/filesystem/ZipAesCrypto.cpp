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

#include <cstring>

VCMI_LIB_NAMESPACE_BEGIN

namespace ZipAes
{

namespace
{

/// AES 的 S 盒
constexpr std::uint8_t substitutionBox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/// 密钥扩展时用到的轮常量
constexpr std::uint8_t roundConstants[11] = {
	0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

constexpr std::size_t blockSize = 16;
constexpr std::size_t sha1DigestLength = 20;
constexpr std::size_t sha1BlockLength = 64;

std::uint32_t rotateLeft(std::uint32_t value, unsigned bits)
{
	return (value << bits) | (value >> (32 - bits));
}

std::uint32_t loadBigEndian(const std::uint8_t * data)
{
	return (static_cast<std::uint32_t>(data[0]) << 24)
	     | (static_cast<std::uint32_t>(data[1]) << 16)
	     | (static_cast<std::uint32_t>(data[2]) << 8)
	     | static_cast<std::uint32_t>(data[3]);
}

void storeBigEndian(std::uint8_t * data, std::uint32_t value)
{
	data[0] = static_cast<std::uint8_t>((value >> 24) & 0xff);
	data[1] = static_cast<std::uint8_t>((value >> 16) & 0xff);
	data[2] = static_cast<std::uint8_t>((value >> 8) & 0xff);
	data[3] = static_cast<std::uint8_t>(value & 0xff);
}

// ---------------------------------------------------------------------------
// SHA-1
// ---------------------------------------------------------------------------

void sha1ProcessBlock(std::uint32_t state[5], const std::uint8_t block[sha1BlockLength])
{
	std::uint32_t schedule[80];

	for(int i = 0; i < 16; ++i)
		schedule[i] = loadBigEndian(block + i * 4);

	for(int i = 16; i < 80; ++i)
		schedule[i] = rotateLeft(schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16], 1);

	std::uint32_t a = state[0];
	std::uint32_t b = state[1];
	std::uint32_t c = state[2];
	std::uint32_t d = state[3];
	std::uint32_t e = state[4];

	for(int i = 0; i < 80; ++i)
	{
		std::uint32_t f = 0;
		std::uint32_t k = 0;

		if(i < 20)
		{
			f = (b & c) | (~b & d);
			k = 0x5a827999u;
		}
		else if(i < 40)
		{
			f = b ^ c ^ d;
			k = 0x6ed9eba1u;
		}
		else if(i < 60)
		{
			f = (b & c) | (b & d) | (c & d);
			k = 0x8f1bbcdcu;
		}
		else
		{
			f = b ^ c ^ d;
			k = 0xca62c1d6u;
		}

		const std::uint32_t temporary = rotateLeft(a, 5) + f + e + k + schedule[i];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = temporary;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;

	secureErase(schedule, sizeof(schedule));
}

// ---------------------------------------------------------------------------
// AES 内部步骤
// ---------------------------------------------------------------------------

std::uint32_t substituteWord(std::uint32_t word)
{
	return (static_cast<std::uint32_t>(substitutionBox[(word >> 24) & 0xff]) << 24)
	     | (static_cast<std::uint32_t>(substitutionBox[(word >> 16) & 0xff]) << 16)
	     | (static_cast<std::uint32_t>(substitutionBox[(word >> 8) & 0xff]) << 8)
	     | static_cast<std::uint32_t>(substitutionBox[word & 0xff]);
}

void expandKey(AesContext & context, const std::uint8_t * key, int keyWords)
{
	const int totalWords = 4 * (context.rounds + 1);

	for(int i = 0; i < keyWords; ++i)
		context.roundKeys[i] = loadBigEndian(key + i * 4);

	for(int i = keyWords; i < totalWords; ++i)
	{
		std::uint32_t temporary = context.roundKeys[i - 1];

		if(i % keyWords == 0)
			temporary = substituteWord(rotateLeft(temporary, 8)) ^ (static_cast<std::uint32_t>(roundConstants[i / keyWords]) << 24);
		else if(keyWords > 6 && i % keyWords == 4)
			temporary = substituteWord(temporary);

		context.roundKeys[i] = context.roundKeys[i - keyWords] ^ temporary;
	}
}

void addRoundKey(std::uint8_t state[blockSize], const std::uint32_t * roundKey)
{
	for(int i = 0; i < 4; ++i)
	{
		state[i * 4 + 0] ^= static_cast<std::uint8_t>((roundKey[i] >> 24) & 0xff);
		state[i * 4 + 1] ^= static_cast<std::uint8_t>((roundKey[i] >> 16) & 0xff);
		state[i * 4 + 2] ^= static_cast<std::uint8_t>((roundKey[i] >> 8) & 0xff);
		state[i * 4 + 3] ^= static_cast<std::uint8_t>(roundKey[i] & 0xff);
	}
}

void substituteBytes(std::uint8_t state[blockSize])
{
	for(int i = 0; i < 16; ++i)
		state[i] = substitutionBox[state[i]];
}

/// state 的下标是 row + 4 * column，第 r 行循环左移 r 个字节
void shiftRows(std::uint8_t state[blockSize])
{
	std::uint8_t temporary = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = temporary;

	temporary = state[2];
	state[2] = state[10];
	state[10] = temporary;
	temporary = state[6];
	state[6] = state[14];
	state[14] = temporary;

	temporary = state[3];
	state[3] = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = temporary;
}

std::uint8_t multiplyByTwo(std::uint8_t value)
{
	return static_cast<std::uint8_t>((value << 1) ^ ((value & 0x80) ? 0x1b : 0x00));
}

void mixColumns(std::uint8_t state[blockSize])
{
	for(int column = 0; column < 4; ++column)
	{
		std::uint8_t * c = state + column * 4;
		const std::uint8_t a0 = c[0];
		const std::uint8_t a1 = c[1];
		const std::uint8_t a2 = c[2];
		const std::uint8_t a3 = c[3];
		const std::uint8_t combined = a0 ^ a1 ^ a2 ^ a3;

		c[0] = static_cast<std::uint8_t>(a0 ^ combined ^ multiplyByTwo(a0 ^ a1));
		c[1] = static_cast<std::uint8_t>(a1 ^ combined ^ multiplyByTwo(a1 ^ a2));
		c[2] = static_cast<std::uint8_t>(a2 ^ combined ^ multiplyByTwo(a2 ^ a3));
		c[3] = static_cast<std::uint8_t>(a3 ^ combined ^ multiplyByTwo(a3 ^ a0));
	}
}

/// CTR 用的计数器是 128 位小端整数
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
// SHA-1
// ---------------------------------------------------------------------------

void sha1Init(Sha1Context & context)
{
	context.state[0] = 0x67452301u;
	context.state[1] = 0xefcdab89u;
	context.state[2] = 0x98badcfeu;
	context.state[3] = 0x10325476u;
	context.state[4] = 0xc3d2e1f0u;
	context.totalLength = 0;
	context.bufferedLength = 0;
}

void sha1Update(Sha1Context & context, const void * data, std::size_t length)
{
	const std::uint8_t * bytes = static_cast<const std::uint8_t *>(data);
	context.totalLength += length;

	if(context.bufferedLength > 0)
	{
		const std::size_t take = std::min(sha1BlockLength - context.bufferedLength, length);
		std::memcpy(context.buffer + context.bufferedLength, bytes, take);
		context.bufferedLength += take;
		bytes += take;
		length -= take;

		if(context.bufferedLength == sha1BlockLength)
		{
			sha1ProcessBlock(context.state, context.buffer);
			context.bufferedLength = 0;
		}
	}

	while(length >= sha1BlockLength)
	{
		sha1ProcessBlock(context.state, bytes);
		bytes += sha1BlockLength;
		length -= sha1BlockLength;
	}

	if(length > 0)
	{
		std::memcpy(context.buffer, bytes, length);
		context.bufferedLength = length;
	}
}

void sha1Final(Sha1Context & context, std::uint8_t digest[sha1DigestLength])
{
	const std::uint64_t bitLength = context.totalLength * 8;

	context.buffer[context.bufferedLength++] = 0x80;

	// 这一块剩下的位置放不下 8 字节长度时，先把这块凑满处理掉
	if(context.bufferedLength > 56)
	{
		while(context.bufferedLength < sha1BlockLength)
			context.buffer[context.bufferedLength++] = 0x00;

		sha1ProcessBlock(context.state, context.buffer);
		context.bufferedLength = 0;
	}

	while(context.bufferedLength < 56)
		context.buffer[context.bufferedLength++] = 0x00;

	// 末尾 8 字节是大端表示的总位长
	for(int i = 0; i < 8; ++i)
		context.buffer[56 + i] = static_cast<std::uint8_t>((bitLength >> (56 - i * 8)) & 0xff);

	sha1ProcessBlock(context.state, context.buffer);

	for(int i = 0; i < 5; ++i)
		storeBigEndian(digest + i * 4, context.state[i]);

	secureErase(&context, sizeof(context));
}

// ---------------------------------------------------------------------------
// HMAC-SHA1
// ---------------------------------------------------------------------------

namespace
{

/// 把密码字节 XOR 进 HMAC 需要的两个 pad 块
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
		// 密码比一个 SHA-1 block 还长：按规范得先对密码做一次 SHA-1
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

void hmacSha1Init(HmacSha1Context & context, const PasswordByteSource & password)
{
	// 直接以 pad 值为底、把密码字节 XOR 进来，不经过「先拼出一份完整密码」这一步
	std::uint8_t innerPad[sha1BlockLength];
	std::uint8_t outerPad[sha1BlockLength];
	std::memset(innerPad, 0x36, sizeof(innerPad));
	std::memset(outerPad, 0x5c, sizeof(outerPad));

	PadFiller filler;
	filler.innerPad = innerPad;
	filler.outerPad = outerPad;

	const bool replayed = password.replay != nullptr
	                   && password.replay(password.context, &fillPadBlock, &filler);

	if(replayed && filler.tooLong)
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

	// 来源失效时按空密码收尾：算出来的密钥是错的，解密必然失败，
	// 不会悄悄放行一份错误内容
	sha1Init(context.inner);
	sha1Update(context.inner, innerPad, sha1BlockLength);

	sha1Init(context.outer);
	sha1Update(context.outer, outerPad, sha1BlockLength);

	secureErase(innerPad, sizeof(innerPad));
	secureErase(outerPad, sizeof(outerPad));
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
	// WinZip AES 的 salt 最多 16 字节，这里留足余量并做一次边界检查
	constexpr std::size_t maxSaltLength = 64;

	if(iterations == 0 || saltLength > maxSaltLength)
		return;

	std::uint8_t saltBlock[maxSaltLength + 4];
	std::memcpy(saltBlock, salt, saltLength);

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

		// 每次迭代都重新从密码源取一遍密码：代价是每条目多几千次重放，
		// 换来的是内存里不存在一份完整的密码
		HmacSha1Context hmac;
		hmacSha1Init(hmac, password);
		hmacSha1Update(hmac, saltBlock, saltLength + 4);
		hmacSha1Final(hmac, current);

		std::memcpy(accumulated, current, sha1DigestLength);

		for(std::uint32_t iteration = 1; iteration < iterations; ++iteration)
		{
			hmacSha1Init(hmac, password);
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
// AES
// ---------------------------------------------------------------------------

void aesInit(AesContext & context, Strength strength, const std::uint8_t * key)
{
	const int keyWords = strength == Strength::Aes128 ? 4
	                   : strength == Strength::Aes192 ? 6
	                   : 8;

	context.rounds = keyWords + 6;

	expandKey(context, key, keyWords);
}

void aesEncryptBlock(const AesContext & context, const std::uint8_t input[blockSize], std::uint8_t output[blockSize])
{
	std::uint8_t state[blockSize];
	std::memcpy(state, input, sizeof(state));

	addRoundKey(state, context.roundKeys);

	for(int round = 1; round < context.rounds; ++round)
	{
		substituteBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, context.roundKeys + round * 4);
	}

	// 最后一轮不做 MixColumns
	substituteBytes(state);
	shiftRows(state);
	addRoundKey(state, context.roundKeys + context.rounds * 4);

	std::memcpy(output, state, sizeof(state));
	secureErase(state, sizeof(state));
}

void aesCtrInit(AesCtrContext & context, Strength strength, const std::uint8_t * key)
{
	aesInit(context.cipher, strength, key);

	std::memset(context.counter, 0, sizeof(context.counter));
	context.counter[0] = 1;

	context.streamUsed = sizeof(context.stream);
}

void aesCtrCrypt(AesCtrContext & context, std::uint8_t * data, std::size_t length)
{
	for(std::size_t i = 0; i < length; ++i)
	{
		if(context.streamUsed == sizeof(context.stream))
		{
			aesEncryptBlock(context.cipher, context.counter, context.stream);
			incrementCounter(context.counter);
			context.streamUsed = 0;
		}

		data[i] ^= context.stream[context.streamUsed++];
	}
}

// ---------------------------------------------------------------------------
// 密钥派生
// ---------------------------------------------------------------------------

void deriveAesKeys(Strength strength, const PasswordByteSource & password,
                   const std::uint8_t * salt, AesKeyMaterial & keys)
{
	const std::size_t length = keyLength(strength);

	// 一次 PBKDF2 出 (2 * 密钥长度 + 2) 字节，再按规范顺序切开
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
	volatile std::uint8_t * bytes = static_cast<volatile std::uint8_t *>(data);

	while(length > 0)
	{
		*bytes = 0;
		++bytes;
		--length;
	}
}

}

VCMI_LIB_NAMESPACE_END
