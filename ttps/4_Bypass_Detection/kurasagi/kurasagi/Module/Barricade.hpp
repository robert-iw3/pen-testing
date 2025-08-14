/*
 * @file Barricade.hpp
 * @brief Implementation of Barricade method to bypass PatchGuard
 */

#pragma once

#include "../Include.hpp"

namespace wsbp {

	/*
	 * Barricade method is so powerful.
	 * It will automatically bypass APC method, thread method, DPC hook method.
	 * It is for extra safety and stack-tracing.
	 */
	namespace Barricade {

		/*
		 * @brief Flip (by individual processors) PTE's NX bit.
		 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
		 */
		VOID FlipPteNxBit();
		BOOLEAN FlipPteNxBitIdPc(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

		/*
		 * @brief Inject Custom Interrupt Handler (specifically for Execute Access handler)
		 * @details Inject it directly to IDT so we can handle it.
		 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
		 */
		BOOLEAN InjectCustomInterruptHandler();

		/*
		 * @brief Desiring custom NX fault handler.
		 * @returns `TRUE` if handled. `FALSE` otherwise. the wrapout routine is `HkMmAccessFault`.
		 */
		BOOLEAN CustomNxFaultHandler(void* faultAddress, PKTRAP_FRAME trapFrame);
		extern NTSTATUS(NTAPI* OrigMmAccessFault)(_In_ ULONG, _In_ PVOID, _In_ KPROCESSOR_MODE, _In_ PVOID);
		NTSTATUS NTAPI HkMmAccessFault(
			_In_ ULONG FaultCode,
			_In_ PVOID Address,
			_In_ KPROCESSOR_MODE Mode,
			_In_ PVOID TrapInformation
		);

		/*
		 * @brief Setup Barricade.
		 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
		 */
		BOOLEAN SetupBarricade();

	}
}