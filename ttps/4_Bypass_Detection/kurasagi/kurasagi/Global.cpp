/*
 * @file Global.cpp
 * @brief Implementation of Global.hpp
 */

#include "Global.hpp"
#include "Log.hpp"

void* gl::RtVar::KernelBase = NULL;
ULONG64* gl::RtVar::KiWaitAlwaysPtr = NULL;
ULONG64* gl::RtVar::KiWaitNeverPtr = NULL;
void* gl::RtVar::KeBugCheckExPtr = NULL;
void* (*gl::RtVar::KeGetCurrentPrcbPtr)() = NULL;
void* gl::RtVar::CcBcbProfilerPtr = NULL;
void* gl::RtVar::CcBcbProfiler2Ptr = NULL;
void* gl::RtVar::MaxDataSizePtr = NULL;
void* gl::RtVar::KiSwInterruptDispatchPtr = NULL;
void* gl::RtVar::KiMcaDeferredRecoveryServicePtr = NULL;
void** gl::RtVar::MiVisibleStatePtr = NULL;
void* gl::RtVar::KeDelayExecutionThreadPtr = NULL;
void* gl::RtVar::KeWaitForMultipleObjectsPtr = NULL;
void* gl::RtVar::KeWaitForSingleObjectPtr = NULL;
NTSTATUS(NTAPI* gl::RtVar::MmAccessFaultPtr)(_In_ ULONG, _In_ PVOID, _In_ KPROCESSOR_MODE, _In_ PVOID) = NULL;
void* gl::RtVar::KiPageFaultPtr = NULL;
void* gl::RtVar::KiBalanceSetManagerDeferredRoutinePtr = NULL;
KDPC* gl::RtVar::KiBalanceSetManagerPeriodicDpcPtr = NULL;

uintptr_t gl::RtVar::Pte::MmPdeBase = 0;
uintptr_t gl::RtVar::Pte::MmPdpteBase = 0;
uintptr_t gl::RtVar::Pte::MmPteBase = 0;
uintptr_t gl::RtVar::Pte::MmPml4eBase = 0;

uintptr_t gl::RtVar::Self::SelfBase = NULL;
size_t gl::RtVar::Self::SelfSize = 0;

BOOLEAN gl::RtVar::InitializeRuntimeVariables() {

	// Try to get kernel base by usually known 'PIE-Base trick'
	UNICODE_STRING strKeBugCheckEx;
	RtlInitUnicodeString(&strKeBugCheckEx, L"KeBugCheckEx");
	KeBugCheckExPtr = MmGetSystemRoutineAddress(&strKeBugCheckEx);

	KernelBase = (void*)((uintptr_t)KeBugCheckExPtr - gl::Offsets::KeBugCheckExOff);

	if (((uintptr_t)KernelBase & 0xFFF) != 0) {
		LogError("InitializeRuntimeVariables: Base mismatch! Please update offsets");
		return FALSE;
	}

	if (((PIMAGE_DOS_HEADER)KernelBase)->e_magic != IMAGE_DOS_SIGNATURE) {
		LogError("InitializeRuntimeVariables: DOS Signature verify failed");
		return FALSE;
	}

	KiWaitAlwaysPtr = (ULONG64*)((uintptr_t)KernelBase + gl::Offsets::KiWaitAlwaysOff);
	KiWaitNeverPtr = (ULONG64*)((uintptr_t)KernelBase + gl::Offsets::KiWaitNeverOff);
	KeGetCurrentPrcbPtr = (void* (*)())((uintptr_t)KernelBase + gl::Offsets::KeGetCurrentPrcbOff);
	CcBcbProfilerPtr = (void*)((uintptr_t)KernelBase + gl::Offsets::CcBcbProfilerOff);
	CcBcbProfiler2Ptr = (void*)((uintptr_t)KernelBase + gl::Offsets::CcBcbProfiler2Off);
	KiSwInterruptDispatchPtr = (void*)((uintptr_t)KernelBase + gl::Offsets::KiSwInterruptDispatchOff);
	MaxDataSizePtr = (void*)((uintptr_t)KernelBase + gl::Offsets::MaxDataSizeOff);
	KiMcaDeferredRecoveryServicePtr = (void*)((uintptr_t)KernelBase + gl::Offsets::KiMcaDeferredRecoveryServiceOff);
	MiVisibleStatePtr = (void**)((uintptr_t)KernelBase + gl::Offsets::MiVisibleStateOff);
	KeDelayExecutionThreadPtr = (void*)((uintptr_t)KernelBase + gl::Offsets::KeDelayExecutionTheadOff);
	KeWaitForSingleObjectPtr = (void*)((uintptr_t)KernelBase + gl::Offsets::KeWaitForSingleObjectOff);
	KeWaitForMultipleObjectsPtr = (void*)((uintptr_t)KernelBase + gl::Offsets::KeWaitForMultipleObjectsOff);
	MmAccessFaultPtr = (NTSTATUS(NTAPI*)(_In_ ULONG, _In_ PVOID, _In_ KPROCESSOR_MODE, _In_ PVOID))((uintptr_t)KernelBase + gl::Offsets::MmAccessFaultOff);
	KiPageFaultPtr = (void*)((uintptr_t)KernelBase + gl::Offsets::KiPageFaultOff);
	KiBalanceSetManagerPeriodicDpcPtr = (KDPC*)((uintptr_t)KernelBase + gl::Offsets::KiBalanceSetManagerPeriodicDpcOff);
	KiBalanceSetManagerDeferredRoutinePtr = (void*)((uintptr_t)KernelBase + gl::Offsets::KiBalanceSetManagerDeferredRoutineOff);

	Pte::MmPteBase = *(uintptr_t*)((uintptr_t)KernelBase + gl::Offsets::MmPteBaseOff);

	size_t selfRefIndex = (Pte::MmPteBase >> 39) & 0x1FF;
	uintptr_t base = Pte::MmPteBase;

	base |= (selfRefIndex << 30);
	Pte::MmPdeBase = base;
	base |= (selfRefIndex << 21);
	Pte::MmPdpteBase = base;
	base |= (selfRefIndex << 12);
	Pte::MmPml4eBase = base;
	
	Self::SelfBase = (uintptr_t)&__ImageBase;
	Self::SelfSize = (uintptr_t)&__end - Self::SelfBase;

	return TRUE;
}