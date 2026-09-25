/*
 * AntiDebug.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "AntiDebug.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>

#if defined(VCMI_WINDOWS)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#elif defined(VCMI_MAC)
#  include <sys/sysctl.h>
#  include <sys/types.h>
#  include <unistd.h>
#elif defined(VCMI_UNIX)
#  include <cstdio>
#  include <cstdlib>
#  include <cstring>
#endif

VCMI_LIB_NAMESPACE_BEGIN

namespace ModPassword
{

// MODPASSWORD_ANTIDEBUG 由 CMake 只在 Release 配置下传入；
// MODPASSWORD_NO_ANTIDEBUG 是手工强制关闭的开关。两者都不满足时整个模块编译成空。
#if !defined(MODPASSWORD_ANTIDEBUG) || defined(MODPASSWORD_NO_ANTIDEBUG)

std::uint8_t antiDebugBias()
{
	return 0;
}

#else

namespace
{

/// 命中时叠到掩码上的偏置。与 maskBias() 取不同的值，
/// 两者同时生效时还原出来的密码同样是错的。
constexpr std::uint8_t detectionBias = 0x5B;

// ---------------------------------------------------------------------------
// 是否附加了调试器
// ---------------------------------------------------------------------------

#if defined(VCMI_WINDOWS)

/// NtQueryInformationProcess 的两条查询：DebugPort 非零、DebugObjectHandle 非空。
/// 一部分调试器会把 PEB 里的 BeingDebugged 清掉，但这两条仍然会露出来。
///
/// 用 GetModuleHandleA/GetProcAddress 动态取函数地址，而不是直接依赖 ntdll 导入，
/// 是为了不给导入表新增条目。只读取句柄，不做任何设置类操作。
bool debuggerAttachedViaNtdll()
{
	using QueryInformationProcessFn = long (WINAPI *)(HANDLE, unsigned long, void *, unsigned long, unsigned long *);

	const HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if(ntdll == nullptr)
		return false;

	const auto query = reinterpret_cast<QueryInformationProcessFn>(
	    GetProcAddress(ntdll, "NtQueryInformationProcess"));

	if(query == nullptr)
		return false;

	constexpr unsigned long processDebugPort = 7;
	constexpr unsigned long processDebugObjectHandle = 30;

	ULONG_PTR port = 0;
	if(query(GetCurrentProcess(), processDebugPort, &port, sizeof(port), nullptr) >= 0 && port != 0)
		return true;

	HANDLE handle = nullptr;
	if(query(GetCurrentProcess(), processDebugObjectHandle, &handle, sizeof(handle), nullptr) >= 0 && handle != nullptr)
		return true;

	return false;
}

/// 三条查询都是只读的：问「本进程有没有调试器」，不问「有没有外部代码在动我」。
/// 往进程里注入钩子的叠加层与录屏工具不会命中任何一条。
bool debuggerAttached()
{
	if(IsDebuggerPresent() != FALSE)
		return true;

	BOOL attached = FALSE;
	if(CheckRemoteDebuggerPresent(GetCurrentProcess(), &attached) != FALSE && attached != FALSE)
		return true;

	return debuggerAttachedViaNtdll();
}

#elif defined(VCMI_MAC)

/// 只读查询进程自身的 P_TRACED 标志，没有副作用。
/// 不用 ptrace(PT_DENY_ATTACH)：那会让进程在被附加时直接被杀掉，代价太大。
bool debuggerAttached()
{
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
	struct kinfo_proc info = {};
	std::size_t size = sizeof(info);

	if(sysctl(mib, 4, &info, &size, nullptr, 0) != 0)
		return false;

	return (info.kp_proc.p_flag & P_TRACED) != 0;
}

#elif defined(VCMI_UNIX)

/// 读 /proc/self/status 里的 TracerPid，只读、无副作用。
/// 特意不用 ptrace(PTRACE_TRACEME)：那会永久改变本进程的信号传递语义，
/// 影响崩溃转储和退出行为，对一个游戏客户端来说代价过大。
/// 在没有 /proc 的环境（例如 iOS）上 fopen 失败，按未命中处理。
bool debuggerAttached()
{
	std::FILE * status = std::fopen("/proc/self/status", "r");
	if(status == nullptr)
		return false;

	char line[256] = {};
	bool traced = false;

	while(std::fgets(line, sizeof(line), status) != nullptr)
	{
		if(std::strncmp(line, "TracerPid:", 10) != 0)
			continue;

		traced = std::strtol(line + 10, nullptr, 10) != 0;
		break;
	}

	std::fclose(status);
	return traced;
}

#else

bool debuggerAttached()
{
	return false;
}

#endif

// ---------------------------------------------------------------------------
// 是否在单步执行
// ---------------------------------------------------------------------------

/// 单步执行会让一个已知代价的小循环慢上几个数量级。
///
/// 取多轮测量的最小值：线程被抢占只会让测量值偏大，最小值对系统负载、
/// 虚拟机、CPU 降频都不敏感，所以阈值可以取得很宽 —— 正常机器上这个循环
/// 在百微秒量级，阈值取在两者中间，留出约三个数量级的余量，
/// 意味着只有真正的单步执行（每步一次用户态往返）才会命中。
bool singleSteppingDetected()
{
	constexpr int rounds = 3;
	constexpr int iterations = 20000;
	constexpr auto budget = std::chrono::milliseconds(150);

	volatile std::uint32_t sink = 0;
	std::chrono::steady_clock::duration best = std::chrono::steady_clock::duration::max();

	for(int round = 0; round < rounds; ++round)
	{
		const auto start = std::chrono::steady_clock::now();

		for(int i = 0; i < iterations; ++i)
			sink = sink + static_cast<std::uint32_t>(i);

		best = std::min(best, std::chrono::steady_clock::now() - start);
	}

	return best > budget;
}

}

std::uint8_t antiDebugBias()
{
	/// 调用点是每个密码字节一次，而 AES 那条路每个条目要把密码重放上千遍，
	/// 所以检查必须节流：便宜的两项每 1024 次跑一次，
	/// 昂贵的定时测量每 65536 次跑一次（约每两三个条目一次，摊销后可以忽略）。
	static constexpr std::uint32_t attachedInterval = 1024;
	static constexpr std::uint32_t steppingInterval = 65536;

	static std::atomic<std::uint32_t> calls{0};
	static std::atomic<std::uint8_t> cached{0};

	const std::uint32_t index = calls.fetch_add(1, std::memory_order_relaxed);

	// 首次调用走完整检查，因此「先附加调试器、再让 VCMI 加载加密 Mod」会被立刻抓到
	if(index % steppingInterval == 0)
	{
		const bool hit = debuggerAttached() || singleSteppingDetected();
		cached.store(hit ? detectionBias : std::uint8_t{0}, std::memory_order_relaxed);
	}
	else if(index % attachedInterval == 0)
	{
		cached.store(debuggerAttached() ? detectionBias : std::uint8_t{0}, std::memory_order_relaxed);
	}

	return cached.load(std::memory_order_relaxed);
}

#endif

}

VCMI_LIB_NAMESPACE_END
