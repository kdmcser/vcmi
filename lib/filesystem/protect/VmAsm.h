/*
 * VmAsm.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include "StdInc.h"

#include "vm_key.h" // 由 CMake 生成到构建目录（每个构建目录一份随机映射）

#include <array>
#include <cstdint>

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{
namespace Vm
{

// ---------------------------------------------------------------------------
// 逻辑指令
//
// 真正出现在字节码里的是 permuteOpcode() 置换后的字节，不是下面这些值。
// 置换是一个双射（乘 167 再乘 23 在模 256 下互逆），所以能原样还原。
// ---------------------------------------------------------------------------
enum LogicalOp : std::uint8_t
{
	opEnd = 0,
	opPush8,          // imm8   压入立即数
	opPush32,         // imm32
	opLoadLocal,      // imm8   压入局部变量
	opStoreLocal,     // imm8   弹出并写入局部变量
	opDup,            // 复制栈顶
	opPop,            // 丢弃栈顶
	opAdd,
	opSub,
	opXor,
	opAnd,
	opMul,
	opLessThan,       // a < b ? 1 : 0
	opEqual,          // a == b ? 1 : 0
	opNotEqual,       // a != b ? 1 : 0
	opJump,           // int16  相对下一条指令的偏移
	opJumpIfZero,     // int16  弹出条件，为 0 则跳转
	opJumpIfNotZero,  // int16  弹出条件，非 0 则跳转
	opCallHost,       // imm8   调用宿主函数，返回值压栈
	opLoadBuffer8,    // imm8 bufferId：弹出下标，压入该字节
	opStoreBuffer8,   // imm8 bufferId：弹出值、再弹出下标，写入
	opBufferLength,   // imm8 bufferId：压入长度
	opReturn,         // 弹出返回值并结束
	opCount
};

/// 逻辑指令 -> 物理字节
constexpr std::uint8_t permuteOpcode(std::uint8_t logical)
{
	return static_cast<std::uint8_t>(
	    ((static_cast<std::uint8_t>(logical ^ vmOpcodeKey0) * 167u + vmOpcodeKey1) ^ vmOpcodeXorMask));
}

/// 物理字节 -> 逻辑指令（167 * 23 ≡ 1 mod 256）
constexpr std::uint8_t restoreOpcode(std::uint8_t physical)
{
	return static_cast<std::uint8_t>(
	    ((static_cast<std::uint8_t>(physical ^ vmOpcodeXorMask) - vmOpcodeKey1) * 23u) ^ vmOpcodeKey0);
}

constexpr int maxProgramBytes = 512;
constexpr int maxLabels = 16;

struct Program
{
	std::array<std::uint8_t, maxProgramBytes> bytes{};
	int size = 0;
};

// ---------------------------------------------------------------------------
// 极简汇编器
//
// 用法：在 constexpr 函数里顺序发指令，跳转目标先用标签号占位，finish() 统一回填。
// 因为整个过程都在编译期完成，产物里只有字节码，没有汇编过程本身。
// ---------------------------------------------------------------------------
struct Assembler
{
	Program program{};
	std::array<int, maxLabels> labelOffsets{};
	std::array<int, maxLabels> patchOffsets{};
	std::array<int, maxLabels> patchLabels{};
	int patchCount = 0;

	constexpr void byte(std::uint8_t value)
	{
		program.bytes[static_cast<size_t>(program.size)] = value;
		++program.size;
	}

	constexpr void op(LogicalOp logical)
	{
		byte(permuteOpcode(static_cast<std::uint8_t>(logical)));
	}

	constexpr void imm8(std::uint8_t value)
	{
		byte(value);
	}

	constexpr void imm32(std::uint32_t value)
	{
		byte(static_cast<std::uint8_t>(value & 0xffu));
		byte(static_cast<std::uint8_t>((value >> 8) & 0xffu));
		byte(static_cast<std::uint8_t>((value >> 16) & 0xffu));
		byte(static_cast<std::uint8_t>((value >> 24) & 0xffu));
	}

	/// 定义跳转标签
	constexpr void label(int id)
	{
		labelOffsets[static_cast<size_t>(id)] = program.size;
	}

	/// 带跳转的指令；目标标签允许稍后定义
	constexpr void jump(LogicalOp logical, int id)
	{
		op(logical);
		patchOffsets[static_cast<size_t>(patchCount)] = program.size;
		patchLabels[static_cast<size_t>(patchCount)] = id;
		++patchCount;
		byte(0);
		byte(0);
	}

	constexpr Program finish()
	{
		for(int i = 0; i < patchCount; ++i)
		{
			const int target = labelOffsets[static_cast<size_t>(patchLabels[static_cast<size_t>(i)])];
			const int offset = target - (patchOffsets[static_cast<size_t>(i)] + 2);
			program.bytes[static_cast<size_t>(patchOffsets[static_cast<size_t>(i)])] =
			    static_cast<std::uint8_t>(offset & 0xff);
			program.bytes[static_cast<size_t>(patchOffsets[static_cast<size_t>(i)] + 1)] =
			    static_cast<std::uint8_t>((offset >> 8) & 0xff);
		}
		return program;
	}
};

}
}

VCMI_LIB_NAMESPACE_END
