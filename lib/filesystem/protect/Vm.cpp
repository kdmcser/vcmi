/*
 * Vm.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "Vm.h"

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{
namespace Vm
{

namespace
{

std::int16_t readOffset(const std::uint8_t * code, int position)
{
	const std::uint16_t raw = static_cast<std::uint16_t>(code[position])
	    | static_cast<std::uint16_t>(static_cast<std::uint16_t>(code[position + 1]) << 8);
	return static_cast<std::int16_t>(raw);
}

/// Wipe memory with volatile writes so the compiler cannot optimize them away as dead stores.
/// Platform APIs such as SecureZeroMemory are deliberately avoided to keep this code portable.
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

}

std::uint64_t run(const Program & program, Context & context, const HostFunction * hosts, int hostCount)
{
	const std::uint8_t * code = program.bytes.data();
	int pc = 0;

	for(;;)
	{
		if(pc < 0 || pc >= program.size)
			return 0;

		const std::uint8_t logical = restoreOpcode(code[pc]);
		++pc;

		switch(static_cast<LogicalOp>(logical))
		{
		case opPush8:
			push(context, code[pc]);
			++pc;
			break;

		case opPush32:
			push(context, static_cast<std::uint64_t>(code[pc])
			    | (static_cast<std::uint64_t>(code[pc + 1]) << 8)
			    | (static_cast<std::uint64_t>(code[pc + 2]) << 16)
			    | (static_cast<std::uint64_t>(code[pc + 3]) << 24));
			pc += 4;
			break;

		case opLoadLocal:
			push(context, context.locals[code[pc]]);
			++pc;
			break;

		case opStoreLocal:
			context.locals[code[pc]] = pop(context);
			++pc;
			break;

		case opDup:
			push(context, context.stack.empty() ? 0 : context.stack.back());
			break;

		case opPop:
			pop(context);
			break;

		case opAdd:
		{
			const std::uint64_t right = pop(context);
			const std::uint64_t left = pop(context);
			push(context, left + right);
			break;
		}

		case opSub:
		{
			const std::uint64_t right = pop(context);
			const std::uint64_t left = pop(context);
			push(context, left - right);
			break;
		}

		case opXor:
		{
			const std::uint64_t right = pop(context);
			const std::uint64_t left = pop(context);
			push(context, left ^ right);
			break;
		}

		case opAnd:
		{
			const std::uint64_t right = pop(context);
			const std::uint64_t left = pop(context);
			push(context, left & right);
			break;
		}

		case opMul:
		{
			const std::uint64_t right = pop(context);
			const std::uint64_t left = pop(context);
			push(context, left * right);
			break;
		}

		case opLessThan:
		{
			const std::uint64_t right = pop(context);
			const std::uint64_t left = pop(context);
			push(context, left < right ? 1u : 0u);
			break;
		}

		case opEqual:
		{
			const std::uint64_t right = pop(context);
			const std::uint64_t left = pop(context);
			push(context, left == right ? 1u : 0u);
			break;
		}

		case opNotEqual:
		{
			const std::uint64_t right = pop(context);
			const std::uint64_t left = pop(context);
			push(context, left != right ? 1u : 0u);
			break;
		}

		case opJump:
		{
			const std::int16_t offset = readOffset(code, pc);
			pc += 2;
			pc += offset;
			break;
		}

		case opJumpIfZero:
		{
			const std::int16_t offset = readOffset(code, pc);
			pc += 2;
			if(pop(context) == 0)
				pc += offset;
			break;
		}

		case opJumpIfNotZero:
		{
			const std::int16_t offset = readOffset(code, pc);
			pc += 2;
			if(pop(context) != 0)
				pc += offset;
			break;
		}

		case opCallHost:
		{
			const int index = code[pc];
			++pc;
			push(context, (hosts != nullptr && index < hostCount) ? hosts[index](context) : 0);
			break;
		}

		case opLoadBuffer8:
		{
			const int bufferId = code[pc];
			++pc;
			const std::uint64_t index = pop(context);
			const bool valid = bufferId < bufferCount && index < context.buffers[bufferId].size();
			if(!valid)
				context.failed = true;
			push(context, valid ? context.buffers[bufferId][static_cast<size_t>(index)] : 0);
			break;
		}

		case opStoreBuffer8:
		{
			const int bufferId = code[pc];
			++pc;
			const std::uint64_t value = pop(context);
			const std::uint64_t index = pop(context);
			const bool valid = bufferId < bufferCount && index < context.buffers[bufferId].size();
			if(!valid)
				context.failed = true;
			else
				context.buffers[bufferId][static_cast<size_t>(index)] = static_cast<std::uint8_t>(value);
			break;
		}

		case opBufferLength:
		{
			const int bufferId = code[pc];
			++pc;
			push(context, bufferId < bufferCount ? context.buffers[bufferId].size() : 0);
			break;
		}

		case opReturn:
			return pop(context);

		case opEnd:
		default:
			return 0;
		}
	}
}

void wipe(Context & context)
{
	for(std::uint64_t & value : context.locals)
		eraseBytes(&value, sizeof(value));

	// Wipe by capacity rather than by size: opReturn at the end of the program drains the stack,
	// but the popped values remain in the allocated storage, so wiping only size() would miss these plaintext remnants.
	for(int i = 0; i < bufferCount; ++i)
	{
		if(context.buffers[i].capacity() > 0)
			eraseBytes(context.buffers[i].data(), context.buffers[i].capacity());
	}

	if(context.stack.capacity() > 0)
		eraseBytes(context.stack.data(), context.stack.capacity() * sizeof(std::uint64_t));
}

}
}

VCMI_LIB_NAMESPACE_END
