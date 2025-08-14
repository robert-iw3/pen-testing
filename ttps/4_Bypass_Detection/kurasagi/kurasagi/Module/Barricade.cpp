/*
 * @file Barricade.cpp
 * @brief Implementation for Barricade.hpp
 */

#include "Barricade.hpp"
#include "../Log.hpp"
#include "../Util/Memory.hpp"
#include "../Util/Arith.hpp"
#include "../Global.hpp"

 /* This is a trampoline area, used for storing hooks */
void TrampolineArea() {
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
	DbgBreakPoint();
}

#define HaltNxFault(tf) tf->Rip = *(ULONG64*)tf->Rsp; tf->Rsp += 8
void HaltNxFault2(PKTRAP_FRAME tf) {
	tf->Rsp &= ~0xF; // Align

	// Simulate call KeDelayExecutionThread
	tf->Rcx = (ULONG64)KernelMode;
	tf->Rdx = false;
	*(ULONG64*)(tf->R8 = (tf->Rsp + 0x28)) = (ULONG64)-0x123456789AB000;

	*(ULONG64*)tf->Rsp = tf->Rip;
	tf->Rsp += 8;
	tf->Rip = (ULONG64)gl::RtVar::KeDelayExecutionThreadPtr;

	KeLowerIrql(APC_LEVEL);
	tf->EFlags |= (1 << 9); // enable interrupt
}

/*
 * @brief Return if the ipxe index should be ignored.
 */
BOOLEAN ToIgnoreIpxe(size_t ipxeIndex) {

	UCHAR ipxeVaType = GetPml4eVaType(ipxeIndex);
	if (ipxeVaType == 0xFF) {
		LogInfo("ToIgnoreIpxe: Warning, couldn't fetch pml4 index. (is it usermode?)");
		return TRUE;
	}

	using namespace gl::Constants::MiSystemVaType;

	INT32 toIgnoreList[] = {
		MiVaProcessSpace,
		MiVaDriverImages,
		MiVaPagedPool
	};

	for (auto i : toIgnoreList) {
		if (ipxeVaType == i)
			return TRUE;
	}

	// We should ignore the self referencing pml4e because
	// if we don't, I don't know why but triple fault occurs.. wtf
	if (ipxeIndex == GetPml4Index((PVOID)gl::RtVar::Pte::MmPteBase)) {
		return TRUE;
	}

	return FALSE;
}


NTSTATUS NTAPI wsbp::Barricade::HkMmAccessFault(
	_In_ ULONG FaultCode,
	_In_ PVOID Address,
	_In_ KPROCESSOR_MODE Mode,
	_In_ PVOID TrapInformation
) {
	
	// It should be called from KiPageFault..
	if (_ReturnAddress() == (PVOID)((uintptr_t)gl::RtVar::KiPageFaultPtr + gl::Offsets::FaultingAddressOff)) {

		// The Fault is not occured in user mode, nor it is caused by illegal write access.
		if (!((FaultCode >> 2) & 1) && !((FaultCode >> 1) & 1) && TrapInformation != NULL) {
			
			if (CustomNxFaultHandler(Address, (PKTRAP_FRAME)TrapInformation)) {
				return STATUS_SUCCESS;
			}
		}
	}

	return OrigMmAccessFault(FaultCode, Address, Mode, TrapInformation);
}

BOOLEAN wsbp::Barricade::CustomNxFaultHandler(void* faultAddress, PKTRAP_FRAME trapFrame) {

	size_t pml4Index = GetPml4Index(faultAddress);

	// Ignore the PML4 index if it is in the range of 0-255 (usermode)
	// or if it is in the list of ignored PML4 indices.
	if (pml4Index < 256 || ToIgnoreIpxe(pml4Index)) {
		return FALSE;
	}
	
	void **stack = (void**)(trapFrame->Rsp & ~0b111uLL);
	KIRQL curIrql = KeGetCurrentIrql();

	LogVerbose("NxF: Nx exception caught at %llX", trapFrame->Rip);
	
	// -=-=-=-=-=-=-=-=-=-=-=-= Debug -=-=-=-=-=-=-=-=-=-=-=-=
	
	// copied from WinDbg registers
	LogVerbose("-  RAX:  %llX", trapFrame->Rax);
	LogVerbose("-  RBX:  %llX", trapFrame->Rbx);
	LogVerbose("-  RCX:  %llX", trapFrame->Rcx);
	LogVerbose("-  RDX:  %llX", trapFrame->Rdx);
	LogVerbose("-  RSI:  %llX", trapFrame->Rsi);
	LogVerbose("-  RDI:  %llX", trapFrame->Rdi);
	LogVerbose("-  RSP:  %llX", trapFrame->Rsp);
	LogVerbose("-  RBP:  %llX", trapFrame->Rbp);
	LogVerbose("-   R8:  %llX", trapFrame->R8);
	LogVerbose("-   R9:  %llX", trapFrame->R9);
	LogVerbose("-  R10:  %llX", trapFrame->R10);
	LogVerbose("-  R11:  %llX", trapFrame->R11);
	LogVerbose("- IRQL:  %u", curIrql);

	// I'll add features if it gets detected, currently I think I bypassed all
	// WITHOUT barricade method, so I'll keep it next

	TODO("Add detailed tracing");

	// -=-=-=-=-=-=-=-=-=-=-=-= Debug -=-=-=-=-=-=-=-=-=-=-=-=

	UINT64* pte = GetLastPageTableEntryPointer(faultAddress);

	if (!pte) {
		LogError("NxF: Somehow PTE is not found, couldn't resolve it");
		return FALSE;
	}

	if ((*pte >> 2) & 1) { // User / supervisor
		LogInfo("NxF: User/Supervisor PTE, we do not handle this");
		return FALSE;
	}

	// Let us do individual detection.

	uintptr_t lastValidVp = 0;

	if (curIrql >= DISPATCH_LEVEL) {

		UCHAR* instBytes = (UCHAR*)trapFrame->Rip;

		// CmpAppendDllSection bypass
		if (!memcmp(instBytes, "\x2E\x48\x31", 3) && // The instruction is same
			!IsCanonicalAddress((PVOID)trapFrame->Rdx) && // The key (to decrypt), it is not normal DeferredContext
			trapFrame->Rcx == trapFrame->Rip) {

			LogInfo("NxF: CmpAppendDllSection call detected (%llX), halting", trapFrame->Rip);
			HaltNxFault(trapFrame);

			return TRUE;
		}

		// KiDpcDispatch bypass
		else if (!memcmp(instBytes, "\x48\x31", 2) &&
			!IsCanonicalAddress((PVOID)trapFrame->Rdx) && // Also same, it is not normal DeferredContext
			trapFrame->Rip - 0x60 < trapFrame->Rcx && // I do not want to modify code every kernel update. I saw it [rcx+48h] but it changes frequently.
			trapFrame->Rip + 0x60 > trapFrame->Rcx) { // But this works. so.

			LogInfo("NxF: KiDpcDispatch call detected (%llX), halting", trapFrame->Rip);
			HaltNxFault(trapFrame);

			return TRUE;
		}

		// I do not want to modify code every kernel update.
		// Detect KiTimerDispatch by searching pushfq instruction & after sub rsp, XXX instruction,
		// which is very(?) rare.
		for (size_t i = 0; i < 0x20; i++) {
			if (instBytes[i] == 0x48 && instBytes[i + 1] == 0x9C) { // pushfq
				for (size_t j = i; j < i + 0x20; j++) {
					if (instBytes[j] == 0x48 && instBytes[j + 1] == 0x83) {

						LogInfo("NxF: KiTimerDispatch call detected (%llX), halting", trapFrame->Rip);
						HaltNxFault(trapFrame);

						return TRUE;

					}
				}
			}
		}

		// Currently there are no PG routine that requires more than DISPATCH_LEVEL irql.
		if (curIrql > DISPATCH_LEVEL) {
			LogVerbose("NxF: Current Irql is higher than DISPATCH_LEVEL");
			goto FALSE_POSITIVE;
		}

		if (PsGetCurrentProcess() != PsInitialSystemProcess) {
			LogVerbose("NxF: Current thread is not executed by ntoskrnl");
			goto FALSE_POSITIVE;
		}

		if (KeIsExecutingDpc()) {
			LogVerbose("NxF: Dpc is actually delivered");
			goto FALSE_POSITIVE;
		}

	}

	// Walk stack... Same as FixPgSystemThread
	for (size_t step = 0; step < 0x20; step++) {

		auto* valuePtr = &stack[step];

		// Check sanity with pages.
		if (auto vp = (uintptr_t)valuePtr >> 12; vp != lastValidVp) {
			if (!IsValidAddress((PVOID)valuePtr)) {
				break;
			}
			lastValidVp = vp;
		}

		void* value = *valuePtr;

		// Check if it is matched
		if (value != gl::RtVar::KeDelayExecutionThreadPtr &&
			value != gl::RtVar::KeWaitForMultipleObjectsPtr &&
			value != gl::RtVar::KeWaitForSingleObjectPtr) {
			continue;
		}

		LogInfo("NxF: PatchGuard thread detected, suspending...");
		HaltNxFault2(trapFrame);
		return TRUE;
	}

FALSE_POSITIVE:
	LogVerbose("NxF: False positive, restoring");

	// It should be false positive.
	*pte &= ~(1ULL << 63);
	FlushTlb;

	// We do not process this, the original MmAccessFault will.
	return FALSE;
	
}

BOOLEAN wsbp::Barricade::FlipPteNxBitIdPc(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	auto LambdaRecursePteToFlip = [ ](auto&& self, PVOID virtualAddress, size_t remainingRecurse) {
		
		UINT64* ptEntryPtr = GetPageTableEntryPointer(virtualAddress, remainingRecurse);
		if (!(*ptEntryPtr & 1)) { // not present
			return;
		}
		
		if (remainingRecurse > 1) { // not PTE

			if (!((*ptEntryPtr >> 7) & 0x1)) { // not large page
				
				for (size_t ipte = 0; ipte < 512; ipte++) {
					self(self,
						(PVOID)((uintptr_t)virtualAddress | (ipte << (12 + 9 * (remainingRecurse - 2)))),
						remainingRecurse - 1);
				}
				return;

			}

			// We do process large pages.
			// LogVerbose("LambdaRecursePteToFlip: Large page @ %p", virtualAddress);
		}

		// Check if it is RWX.
		//         Can't Read/Write    or        execute_disable
		if (!((*ptEntryPtr >> 1) & 0x1) || ((*ptEntryPtr >> 63) & 0x1)) {
			return;
		}

		size_t pageSize = 1ULL << (12 + 9 * (remainingRecurse - 1));
		
		// Check if it is our driver code section.
		// We'll get triple fault if we do not.
		if (IsCollapsing((uintptr_t)virtualAddress,
			(uintptr_t)virtualAddress + pageSize - 1,
			gl::RtVar::Self::SelfBase,
			gl::RtVar::Self::SelfBase + gl::RtVar::Self::SelfSize - 1)) {
			LogVerbose("LambdaRecursePteToFlip: Virtual Address %p is in our driver, skipping..", virtualAddress);
			return;
		}

		//LogVerbose("LambdaRecursePteToFlip Flip RWX @ %p", virtualAddress);
		*ptEntryPtr |= (1ULL << 63); // Flip the NX bit.
	};

	// Since we have same PTE base for every core, we can multithread it to improve performance.
	size_t procTotal = KeQueryActiveProcessorCountEx(0);
	size_t procNum = KeGetCurrentProcessorNumberEx(0);

	size_t rangePerCpu = max(256 / procTotal, 1);
	size_t rangeStart = min(256 + procNum * rangePerCpu, 512);
	size_t rangeEnd = min(256 + (procNum + 1) * rangePerCpu, 512);

	if (procNum == procTotal - 1) {
		rangeEnd = 512;
	}

	LogVerbose("FlipPteNxBitIdPc: CPU %llu doing [%llu, %llu)", procNum, rangeStart, rangeEnd);

	for (size_t ipxe = rangeStart; ipxe < rangeEnd; ipxe++) { // Iterate PML4s to initiate the recursive routine.
		if (ToIgnoreIpxe(ipxe)) {
			continue;
		}

		LambdaRecursePteToFlip(LambdaRecursePteToFlip,
			MakeCanonicalAddress((PVOID)(ipxe << 39)),
			4);
	}

	// Lastly flush TLB.
	FlushTlb;

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);

	return TRUE;
}

VOID wsbp::Barricade::FlipPteNxBit() {

	// This also need to be processed on individual processor.
	KeGenericCallDpc((PKDEFERRED_ROUTINE)FlipPteNxBitIdPc, NULL);

	LogInfo("FlipPteNxBit: Done.");

	return;
}

BOOLEAN wsbp::Barricade::InjectCustomInterruptHandler() {

	if (!Hook::HookTrampoline(gl::RtVar::MmAccessFaultPtr, HkMmAccessFault, TrampolineArea, gl::Constants::MmAccessFaultInstSize)) {
		LogError("InjectCustomInterruptHandler: Couldn't initiate hook for MmAccessFault");
		return FALSE;
	}

	LogInfo("InjectCustomInterruptHandler: Done.");

	return TRUE;
}

BOOLEAN wsbp::Barricade::SetupBarricade() {

	if (!InjectCustomInterruptHandler()) {
		LogError("SetupBarricade: Couldn't inject custom interrupt handler");
		return FALSE;
	}

	FlipPteNxBit();

	LogInfo("SetupBarricade: Barricade was successfully set up.");

	return TRUE;
}

NTSTATUS(NTAPI* wsbp::Barricade::OrigMmAccessFault)(_In_ ULONG, _In_ PVOID, _In_ KPROCESSOR_MODE, _In_ PVOID) = 
	(NTSTATUS(NTAPI *)(_In_ ULONG, _In_ PVOID, _In_ KPROCESSOR_MODE, _In_ PVOID))(TrampolineArea);
