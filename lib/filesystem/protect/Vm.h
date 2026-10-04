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

/// Number of byte buffers: the protected logic uses them to hold intermediate data such as ciphertext and mask
constexpr int bufferCount = 4;

struct Context
{
	std::uint64_t locals[maxLocals] = {};
	std::vector<std::uint64_t> stack;
	std::vector<std::uint8_t> buffers[bufferCount];

	/// Parameter structure specific to each protected logic; the host functions handle the conversion
	void * parameters = nullptr;

	/// Flag set when a host function reports an error (e.g. a length mismatch)
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

/// Execute the bytecode, returning the value popped from the stack by opReturn
std::uint64_t run(const Program & program, Context & context, const HostFunction * hosts, int hostCount);

/// Wipe buffers and locals so that plaintext does not linger in memory
void wipe(Context & context);

}
}

VCMI_LIB_NAMESPACE_END
