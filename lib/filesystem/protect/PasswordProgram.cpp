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

/// VM 运行期需要的参数
struct Parameters
{
	ZipCryptoKeys * keys = nullptr;

	/// 逐字节接收密码的消费者（AES 的密钥派生用；ZipCrypto 那条路不用）
	PasswordByteConsumer consumer = nullptr;
	void * consumerContext = nullptr;
};

/// 字节码被改动时给掩码叠的偏置；0 表示没被改动
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

/// 用 volatile 写来擦除内存，避免被编译器当成无用赋值优化掉
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

/// 宿主函数 0：把 base64 密文解码到 buffers[0]，返回长度
std::uint64_t hostDecodeCipher(Context & context)
{
	std::string cipher = secretCipher();
	context.buffers[0] = base64Decode(cipher);
	eraseBytes(cipher.data(), cipher.size());
	return context.buffers[0].size();
}

/// 宿主函数 1：弹出下标，返回掩码对应字节
std::uint64_t hostMaskByte(Context & context)
{
	const std::uint64_t index = pop(context);

	// 两个偏置都直接进入密码字节流，不存在"把某个检查改成 true"就能绕过的地方：
	// 字节码被改动时给的是错的掩码，被调试时给的是带偏置的掩码，
	// 两种情况算出来的密码都是错的，下一步解密会明确失败
	const std::uint8_t bias = static_cast<std::uint8_t>(maskBias() ^ antiDebugBias());

	return static_cast<std::uint8_t>(secretMaskByte(static_cast<std::size_t>(index)) ^ bias);
}

/// 宿主函数 2：弹出明文密码字节，直接喂进 ZipCrypto 密钥表
std::uint64_t hostFeedPasswordByte(Context & context)
{
	auto * parameters = static_cast<Parameters *>(context.parameters);
	const std::uint64_t value = pop(context);

	if(parameters->keys != nullptr)
		zipCryptoFeedPassword(*parameters->keys, static_cast<std::uint8_t>(value));

	return 0;
}

/// 宿主函数 3：弹出明文密码字节，交给调用方指定的消费者（AES 的密钥派生用）
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

/// 密码还原逻辑：明文 = base64 解码(密文) ⊕ 掩码
///
/// 算出来的每个字节都直接交给宿主函数 feedHost 消费，不落进任何缓冲区 ——
/// 2 是 ZipCrypto 的密钥表，3 是调用方指定的消费者（AES 的密钥派生）。
constexpr Program buildPasswordProgram(int feedHost)
{
	Assembler assembler;

	// len = 密文长度
	assembler.op(opCallHost);
	assembler.imm8(0);
	assembler.op(opStoreLocal);
	assembler.imm8(0);

	// i = 0
	assembler.op(opPush8);
	assembler.imm8(0);
	assembler.op(opStoreLocal);
	assembler.imm8(1);

	assembler.label(0); // 循环开始
	assembler.op(opLoadLocal);
	assembler.imm8(1);
	assembler.op(opLoadLocal);
	assembler.imm8(0);
	assembler.op(opLessThan);
	assembler.jump(opJumpIfZero, 1); // i >= len 时结束

	assembler.op(opLoadLocal);
	assembler.imm8(1); // 下标
	assembler.op(opLoadBuffer8);
	assembler.imm8(0);
	assembler.op(opStoreLocal);
	assembler.imm8(2); // 密文字节

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

	assembler.label(1); // 结束
	assembler.op(opLoadLocal);
	assembler.imm8(0);
	assembler.op(opReturn);

	return assembler.finish();
}

constexpr Program keyScheduleProgram = buildPasswordProgram(2);
constexpr Program consumerProgram = buildPasswordProgram(3);

/// 编译期算出的字节码校验值（两份字节码一起算）
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

/// 运行时重算校验值：用 volatile 读，避免编译器把结果折回常量
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
	// 字节码是常量，偏置算一次就够。AES 那条路每个条目都要把密码重放几千遍，
	// 每一遍的每个字节都要用它，不缓存等于把 CRC 白算几千次。
	// 缓存不会削弱保护：字节码一旦被改动，缓存下来的偏置同样是错的。
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

	// 过程中不产生明文密码缓冲区，这里只需清掉 VM 内部状态
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

	// 过程中不产生明文密码缓冲区，这里只需清掉 VM 内部状态
	wipe(context);

	// 字节码执行失败时密钥状态不可信，复位回初始值让调用方明确解不出来，
	// 而不是拿着半截密钥解出一堆看似成功实则错误的垃圾数据
	if(context.failed)
		zipCryptoReset(keys);
}

}

VCMI_LIB_NAMESPACE_END
