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
};

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
	return secretMaskByte(static_cast<std::size_t>(index));
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

const HostFunction hostTable[] = {
	&hostDecodeCipher,
	&hostMaskByte,
	&hostFeedPasswordByte,
};
constexpr int hostTableSize = 3;

/// 密码还原逻辑：明文 = base64 解码(密文) ⊕ 掩码
///
/// keepPlaintext 为 true 时把结果写进 buffers[0]（导出密码原文，给 AES 的
/// 密钥派生用）；为 false 时只逐字节喂进 ZipCrypto 密钥表，明文不落进任何
/// 缓冲区（ZipCrypto 解包用）。
constexpr Program buildPasswordProgram(bool keepPlaintext)
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

	if(keepPlaintext)
	{
		assembler.op(opStoreLocal);
		assembler.imm8(3); // 明文
		assembler.op(opLoadLocal);
		assembler.imm8(1); // 下标
		assembler.op(opLoadLocal);
		assembler.imm8(3);
		assembler.op(opStoreBuffer8);
		assembler.imm8(0);
	}
	else
	{
		assembler.op(opCallHost);
		assembler.imm8(2); // 喂进密钥表
		assembler.op(opPop);
	}

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

constexpr Program plaintextProgram = buildPasswordProgram(true);
constexpr Program keyScheduleProgram = buildPasswordProgram(false);

}

std::string derivePassword()
{
	Context context;

	const std::uint64_t length = run(plaintextProgram, context, hostTable, hostTableSize);

	std::string password;
	if(!context.failed && length <= context.buffers[0].size())
		password.assign(context.buffers[0].begin(), context.buffers[0].begin() + static_cast<std::size_t>(length));

	// 中间数据用完立刻擦掉
	wipe(context);

	return password;
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
}

void eraseSecret(std::string & text)
{
	if(!text.empty())
		eraseBytes(text.data(), text.size());
}

}

VCMI_LIB_NAMESPACE_END
