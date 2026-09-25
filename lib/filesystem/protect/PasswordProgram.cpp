/*
 * PasswordProgram.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "PasswordProgram.h"

#include "AntiDebug.h"
#include "SecretConstants.h"
#include "Vm.h"
#include "VmAsm.h"

#include <cstdint>
#include <vector>

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{

namespace
{

using namespace Vm;

/// Parameters required by the VM at runtime
struct Parameters
{
	ZipCryptoKeys * keys = nullptr;

	/// Consumer that receives the password byte by byte (used by AES key derivation; not used on the ZipCrypto path)
	PasswordByteConsumer consumer = nullptr;
	void * consumerContext = nullptr;
};

/// Bias folded into the mask when the bytecode has been modified; 0 means unmodified
std::uint8_t maskBias();

std::vector<std::uint8_t> base64Decode(const std::string & encoded)
{
	static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	std::vector<std::uint8_t> result;
	int group[4] = {};
	int index = 0;

	for(char c : encoded)
	{
		if(c == '=')
			break;

		const std::size_t position = alphabet.find(c);
		if(position == std::string::npos)
			continue;

		group[index++] = static_cast<int>(position);

		if(index == 4)
		{
			result.push_back(static_cast<std::uint8_t>((group[0] << 2) + ((group[1] & 0x30) >> 4)));
			result.push_back(static_cast<std::uint8_t>(((group[1] & 0x0F) << 4) + ((group[2] & 0x3C) >> 2)));
			result.push_back(static_cast<std::uint8_t>(((group[2] & 0x03) << 6) + group[3]));
			index = 0;
		}
	}

	if(index > 0)
	{
		for(int i = index; i < 4; ++i)
			group[i] = 0;

		result.push_back(static_cast<std::uint8_t>((group[0] << 2) + ((group[1] & 0x30) >> 4)));
		if(index > 2)
			result.push_back(static_cast<std::uint8_t>(((group[1] & 0x0F) << 4) + ((group[2] & 0x3C) >> 2)));
		if(index > 3)
			result.push_back(static_cast<std::uint8_t>(((group[2] & 0x03) << 6) + group[3]));
	}

	return result;
}

/// Erases memory using volatile writes so the compiler cannot optimize them away as dead stores
void eraseBytes(void * data, std::size_t length)
{
	volatile std::uint8_t * bytes = static_cast<volatile std::uint8_t *>(data);

	while(length > 0)
	{
		*bytes = 0;
		++bytes;
		--length;
	}
}

/// Host function 0: decodes the base64 ciphertext into buffers[0], returns its length
std::uint64_t hostDecodeCipher(Context & context)
{
	std::string cipher = secretCipher();
	context.buffers[0] = base64Decode(cipher);
	eraseBytes(cipher.data(), cipher.size());
	return context.buffers[0].size();
}

/// Host function 1: pops the index, returns the corresponding mask byte
std::uint64_t hostMaskByte(Context & context)
{
	const std::uint64_t index = pop(context);

	// Both biases enter the password byte stream directly, so there is no place where
	// flipping a single check to true would bypass the protection: a modified bytecode
	// yields a wrong mask, and a debugger yields a biased mask; in both cases the
	// computed password is wrong and the subsequent decryption fails outright
	const std::uint8_t bias = static_cast<std::uint8_t>(maskBias() ^ antiDebugBias());

	return static_cast<std::uint8_t>(secretMaskByte(static_cast<std::size_t>(index)) ^ bias);
}

/// Host function 2: pops a plaintext password byte and feeds it straight into the ZipCrypto key schedule
std::uint64_t hostFeedPasswordByte(Context & context)
{
	auto * parameters = static_cast<Parameters *>(context.parameters);
	const std::uint64_t value = pop(context);

	if(parameters->keys != nullptr)
		zipCryptoFeedPassword(*parameters->keys, static_cast<std::uint8_t>(value));

	return 0;
}

/// Host function 3: pops a plaintext password byte and hands it to the caller-provided consumer (used by AES key derivation)
std::uint64_t hostFeedPasswordConsumer(Context & context)
{
	auto * parameters = static_cast<Parameters *>(context.parameters);
	const std::uint64_t value = pop(context);

	if(parameters->consumer != nullptr)
		parameters->consumer(parameters->consumerContext, static_cast<std::uint8_t>(value));

	return 0;
}

const HostFunction hostTable[] = {
	&hostDecodeCipher,
	&hostMaskByte,
	&hostFeedPasswordByte,
	&hostFeedPasswordConsumer,
};
constexpr int hostTableSize = 4;

/// Password recovery logic: plaintext = base64_decode(ciphertext) ⊕ mask
///
/// Every computed byte is consumed directly by host function feedHost and never
/// lands in any buffer -- 2 is the ZipCrypto key schedule, 3 is the caller-provided
/// consumer (AES key derivation).
constexpr Program buildPasswordProgram(int feedHost)
{
	Assembler assembler;

	// len = ciphertext length
	assembler.op(opCallHost);
	assembler.imm8(0);
	assembler.op(opStoreLocal);
	assembler.imm8(0);

	// i = 0
	assembler.op(opPush8);
	assembler.imm8(0);
	assembler.op(opStoreLocal);
	assembler.imm8(1);

	assembler.label(0); // loop start
	assembler.op(opLoadLocal);
	assembler.imm8(1);
	assembler.op(opLoadLocal);
	assembler.imm8(0);
	assembler.op(opLessThan);
	assembler.jump(opJumpIfZero, 1); // exit when i >= len

	assembler.op(opLoadLocal);
	assembler.imm8(1); // index
	assembler.op(opLoadBuffer8);
	assembler.imm8(0);
	assembler.op(opStoreLocal);
	assembler.imm8(2); // ciphertext byte

	assembler.op(opLoadLocal);
	assembler.imm8(1);
	assembler.op(opCallHost);
	assembler.imm8(1);
	assembler.op(opLoadLocal);
	assembler.imm8(2);
	assembler.op(opXor);

	assembler.op(opCallHost);
	assembler.imm8(static_cast<std::uint8_t>(feedHost));
	assembler.op(opPop);

	assembler.op(opLoadLocal);
	assembler.imm8(1);
	assembler.op(opPush8);
	assembler.imm8(1);
	assembler.op(opAdd);
	assembler.op(opStoreLocal);
	assembler.imm8(1);

	assembler.jump(opJump, 0);

	assembler.label(1); // end
	assembler.op(opLoadLocal);
	assembler.imm8(0);
	assembler.op(opReturn);

	return assembler.finish();
}

constexpr Program keyScheduleProgram = buildPasswordProgram(2);
constexpr Program consumerProgram = buildPasswordProgram(3);

/// Bytecode checksum computed at compile time (both programs are checksummed together)
constexpr std::uint32_t programCheckValue(const Program & program)
{
	std::uint32_t crc = 0xFFFFFFFFu;
	for(int i = 0; i < program.size; ++i)
	{
		crc ^= program.bytes[static_cast<std::size_t>(i)];
		for(int bit = 0; bit < 8; ++bit)
			crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
	}
	return ~crc;
}

constexpr std::uint32_t expectedProgramCheck =
	programCheckValue(keyScheduleProgram) ^ programCheckValue(consumerProgram);

/// Recomputes the checksum at runtime: uses volatile reads so the compiler cannot fold the result back into a constant
std::uint32_t runtimeProgramCheck(const Program & program)
{
	const volatile std::uint8_t * data = program.bytes.data();

	std::uint32_t crc = 0xFFFFFFFFu;
	for(int i = 0; i < program.size; ++i)
	{
		crc ^= data[i];
		for(int bit = 0; bit < 8; ++bit)
			crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
	}
	return ~crc;
}

std::uint8_t maskBias()
{
	// The bytecode is constant, so computing the bias once is enough. On the AES
	// path the password is replayed thousands of times per entry and every byte of
	// every replay uses it, so not caching would waste thousands of CRC computations.
	// Caching does not weaken the protection: once the bytecode is modified, the
	// cached bias is equally wrong.
	static const std::uint8_t cached = []
	{
		const std::uint32_t check =
			runtimeProgramCheck(keyScheduleProgram) ^ runtimeProgramCheck(consumerProgram);

		return check == expectedProgramCheck
		     ? std::uint8_t{0}
		     : static_cast<std::uint8_t>((check >> 8) | 1u);
	}();

	return cached;
}

}

bool derivePasswordBytes(PasswordByteConsumer consumer, void * consumerContext)
{
	Parameters parameters;
	parameters.consumer = consumer;
	parameters.consumerContext = consumerContext;

	Context context;
	context.parameters = &parameters;

	run(consumerProgram, context, hostTable, hostTableSize);

	const bool ok = !context.failed;

	// No plaintext password buffer is produced along the way, so only the VM internal state needs to be wiped here
	wipe(context);

	return ok;
}

void deriveZipCryptoKeys(ZipCryptoKeys & keys)
{
	zipCryptoReset(keys);

	Parameters parameters;
	parameters.keys = &keys;

	Context context;
	context.parameters = &parameters;

	run(keyScheduleProgram, context, hostTable, hostTableSize);

	// No plaintext password buffer is produced along the way, so only the VM internal state needs to be wiped here
	wipe(context);

	// If the bytecode failed to execute the key state is untrustworthy, so reset it to
	// its initial value to make the caller fail cleanly, rather than decrypting garbage
	// that looks plausible but is wrong with a half-initialized key
	if(context.failed)
		zipCryptoReset(keys);
}

}

VCMI_LIB_NAMESPACE_END
