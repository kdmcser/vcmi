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

// MODPASSWORD_ANTIDEBUG is passed in by CMake only for the Release configuration;
// MODPASSWORD_NO_ANTIDEBUG is a manual switch that forces it off. When neither is
// satisfied the whole module compiles to nothing.
#if !defined(MODPASSWORD_ANTIDEBUG) || defined(MODPASSWORD_NO_ANTIDEBUG)

std::uint8_t antiDebugBias()
{
	return 0;
}

#else

namespace
{

/// Bias folded into the mask when triggered. It takes a different value from
/// maskBias(); when both are active the recovered password is equally wrong.
constexpr std::uint8_t detectionBias = 0x5B;

// ---------------------------------------------------------------------------
// Is a debugger attached
// ---------------------------------------------------------------------------

#if defined(VCMI_WINDOWS)

/// Two NtQueryInformationProcess queries: a non-zero DebugPort and a non-null
/// DebugObjectHandle. Some debuggers clear BeingDebugged in the PEB, but these two
/// still give them away.
///
/// The function address is resolved dynamically with GetModuleHandleA/GetProcAddress
/// rather than relying on an ntdll import, so as not to add a new entry to the import
/// table. It only reads handles and performs no setter-style operations.
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

/// All three queries are read-only: they ask "does this process have a debugger"
/// rather than "is external code touching me". Overlay and screen recording tools
/// that inject hooks into the process trigger none of them.
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

/// Read-only query of the process's own P_TRACED flag, with no side effects.
/// ptrace(PT_DENY_ATTACH) is not used: it would kill the process outright on
/// attach, which is too costly.
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

/// Reads TracerPid from /proc/self/status, read-only and side-effect free.
/// ptrace(PTRACE_TRACEME) is deliberately avoided: it would permanently change this
/// process's signal delivery semantics, affecting crash dumps and exit behavior --
/// too costly for a game client.
/// On environments without /proc (for example iOS) fopen fails, which is treated as
/// not triggered.
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
// Is single-stepping in progress
// ---------------------------------------------------------------------------

/// Single-stepping slows a small loop of known cost by several orders of magnitude.
///
/// The minimum over several measurement rounds is taken: thread preemption only
/// inflates the measurement, and the minimum is insensitive to system load, virtual
/// machines, and CPU frequency scaling, so the threshold can be set very loosely --
/// on a normal machine this loop takes on the order of a hundred microseconds, and
/// the threshold sits between the two with roughly three orders of magnitude of
/// headroom, meaning only genuine single-stepping (one user-mode round trip per
/// step) will trigger it.
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
	/// The call site runs once per password byte, and on the AES path the password is
	/// replayed thousands of times per entry, so the checks must be throttled: the two
	/// cheap checks run every 1024 calls, and the expensive timing measurement runs every
	/// 65536 calls (roughly once every two or three entries, negligible when amortized).
	static constexpr std::uint32_t attachedInterval = 1024;
	static constexpr std::uint32_t steppingInterval = 65536;

	static std::atomic<std::uint32_t> calls{0};
	static std::atomic<std::uint8_t> cached{0};

	const std::uint32_t index = calls.fetch_add(1, std::memory_order_relaxed);

	// The first call performs the full check, so "attach the debugger first, then let VCMI load the encrypted Mod" is caught immediately
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
