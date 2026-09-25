/*
 * Vm.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include "StdInc.h"
#include "VmAsm.h"

#include <cstdint>
#include <vector>

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{
namespace Vm
{

constexpr int maxLocals = 16;

/// 字节缓冲区个数：受保护逻辑用它们存放密文、掩码等中间数据
constexpr int bufferCount = 4;

struct Context
{
	std::uint64_t locals[maxLocals] = {};
	std::vector<std::uint64_t> stack;
	std::vector<std::uint8_t> buffers[bufferCount];

	/// 各受保护逻辑自己的参数结构，由宿主函数负责转换
	void * parameters = nullptr;

	/// 宿主函数返回错误（例如长度不符）时的标记
	bool failed = false;
};

using HostFunction = std::uint64_t (*)(Context & context);

inline void push(Context & context, std::uint64_t value)
{
	context.stack.push_back(value);
}

inline std::uint64_t pop(Context & context)
{
	if(context.stack.empty())
	{
		context.failed = true;
		return 0;
	}

	const std::uint64_t value = context.stack.back();
	context.stack.pop_back();
	return value;
}

/// 执行字节码，返回 opReturn 弹栈得到的值
std::uint64_t run(const Program & program, Context & context, const HostFunction * hosts, int hostCount);

/// 擦除缓冲区与局部变量，避免明文留在内存里
void wipe(Context & context);

}
}

VCMI_LIB_NAMESPACE_END
