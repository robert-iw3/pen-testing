/*
 * @file Timer.hpp
 * @brief PatchGuard Timer bypass
 */

#pragma once

#include "../Include.hpp"

typedef struct _KTIMER_TABLE_ENTRY
{
	unsigned __int64 Lock;
	_LIST_ENTRY Entry;
	_ULARGE_INTEGER Time;
} KTIMER_TABLE_ENTRY, * PKTIMER_TABLE_ENTRY;

namespace wsbp {
	namespace Timer {

		/*
		 * @brief Judge if it is PatchGuard Timer.
		 * @param pTimer: Pointer to timer object.
		 * @returns `TRUE` if it is PatchGuard Timer, `FALSE` if it is not PatchGuard Timer.
		 */
		BOOLEAN IsPatchGuardTimer(
			PKTIMER pTimer
		);

		/*
		 * @brief Decrypt KTIMER's DPC content.
		 * @param pTimer: Pointer to timer object.
		 * @returns PKDPC Dpc Object.
		 */
		PKDPC GetDecryptedDpc(
			PKTIMER pTimer
		);

		/*
		 * @brief Disables PatchGuard Timers.
		 * @returns None
		 */
		VOID DisablePatchGuardTimers();
		BOOLEAN DisablePatchGuardTimersIdPc(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

		/*
		 * @brief Restore PatchGuard Timer Hook.
		 */
		VOID RestorePgTimerHook();

		/*
		 * @brief Disables all timers.
		 * @returns `TRUE` if success, `FALSE` otherwise.
		 */
		BOOLEAN DisableAllTimers();
	}
}