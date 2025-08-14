/*
 * @file Global.hpp
 * @brief Global definitions, structs, and etc..
 */

#pragma once

#include "Include.hpp"

namespace gl {

	namespace Constants {
		const size_t TimerTableEntryCount = 512;

		namespace MiSystemVaType {
			constexpr INT32 MiVaUnused = 0x0;
			constexpr INT32 MiVaProcessSpace = 0x1;
			constexpr INT32 MiVaBootLoaded = 0x2;
			constexpr INT32 MiVaPfnDatabase = 0x3;
			constexpr INT32 MiVaNonPagedPool = 0x4;
			constexpr INT32 MiVaPagedPool = 0x5;
			constexpr INT32 MiVaNonCachedMappings = 0x6;
			constexpr INT32 MiVaSystemCache = 0x7;
			constexpr INT32 MiVaSystemPtes = 0x8;
			constexpr INT32 MiVaHal = 0x9;
			constexpr INT32 MiVaNonCachedMappingsLarge = 0xa;
			constexpr INT32 MiVaDriverImages = 0xb;
			constexpr INT32 MiVaSystemPtesLarge = 0xc;
			constexpr INT32 MiVaKernelStacks = 0xd;
			constexpr INT32 MiVaSecureNonPagedPool = 0xe;
			constexpr INT32 MiVaKernelShadowStacks = 0xf;
			constexpr INT32 MiVaSoftWsles = 0x10;
			constexpr INT32 MiVaSystemDataViews = 0x11;
			constexpr INT32 MiVaKernelControlFlowGuard = 0x12;
			constexpr INT32 MiVaKasan = 0x13;
			constexpr INT32 MiVaMaximumType = 0x14;
		}

		const size_t MmAccessFaultInstSize = 15;
	}

	namespace Offsets {

		// Function Offsets.
		const size_t KiWaitAlwaysOff = 0xFC6260;
		const size_t KiWaitNeverOff = 0xFC5F80;
		const size_t KeBugCheckExOff = 0x5005D0;
		const size_t KeGetCurrentPrcbOff = 0x449220;
		const size_t CcBcbProfilerOff = 0x50C8B0;
		const size_t CcBcbProfiler2Off = 0x6F86E0;
		const size_t MaxDataSizeOff = 0xFC5A48;
		const size_t KiSwInterruptDispatchOff = 0x50D4C0;
		const size_t KiMcaDeferredRecoveryServiceOff = 0x6B04A0;
		const size_t MiVisibleStateOff = 0xFC44C0;
		const size_t MmPteBaseOff = 0xFC4478;
		const size_t KeDelayExecutionTheadOff = 0x28FF70;
		const size_t KeWaitForMultipleObjectsOff = 0x291A50;
		const size_t KeWaitForSingleObjectOff = 0x324760;
		const size_t MmAccessFaultOff = 0x2AE130;
		const size_t KiPageFaultOff = 0x6B4540;
		const size_t KiBalanceSetManagerDeferredRoutineOff = 0x4A0140;
		const size_t KiBalanceSetManagerPeriodicDpcOff = 0xF21AA0;

		// Timer
		const size_t PrcbTimerTableOff = 0x4100;
		const size_t TimerTableEntryOff = 0x200;
		const size_t HalReservedOff = 0x48;
		const size_t AcpiReservedOff = 0xE0;

		// MiVisibleState
		const size_t SystemVaTypeOff = 0x1468;

		// KiPageFault->MmAccessFault
		const size_t FaultingAddressOff = 0x386 + 0x5;
	}

	namespace RtVar {

		extern void* KernelBase;
		extern ULONG64* KiWaitAlwaysPtr;
		extern ULONG64* KiWaitNeverPtr;
		extern void* KeBugCheckExPtr;
		extern void* (*KeGetCurrentPrcbPtr)();
		extern void* CcBcbProfilerPtr;
		extern void* CcBcbProfiler2Ptr;
		extern void* MaxDataSizePtr;
		extern void* KiSwInterruptDispatchPtr;
		extern void* KiMcaDeferredRecoveryServicePtr;
		extern void** MiVisibleStatePtr;
		extern void* KeDelayExecutionThreadPtr;
		extern void* KeWaitForMultipleObjectsPtr;
		extern void* KeWaitForSingleObjectPtr;
		extern NTSTATUS(NTAPI* MmAccessFaultPtr)(_In_ ULONG, _In_ PVOID, _In_ KPROCESSOR_MODE, _In_ PVOID);
		extern void* KiPageFaultPtr;
		extern void* KiBalanceSetManagerDeferredRoutinePtr;
		extern KDPC* KiBalanceSetManagerPeriodicDpcPtr;

		namespace Pte {
			extern uintptr_t MmPteBase;
			extern uintptr_t MmPdeBase;
			extern uintptr_t MmPdpteBase;
			extern uintptr_t MmPml4eBase;
		}

		namespace Self {
			extern uintptr_t SelfBase;
			extern size_t SelfSize;
		}

		/*
		 * @brief Initialize `RtVar` variables, which is known at runtime.
		 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
		 */
		BOOLEAN InitializeRuntimeVariables();
	}
}

constexpr auto KURASAGI_POOL_TAG = 'Krsg';

extern "C" IMAGE_DOS_HEADER __ImageBase;

#pragma section(".endsec", read)
__declspec(allocate(".endsec")) const char __end = 0;

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define TODO(msg) __pragma(message(__FILE__ "(" STRINGIZE(__LINE__) "): TODO: " msg))