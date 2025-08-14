/*
 * @file Context7.hpp
 * @brief Bypass the context 7 (in KiInitializePatchGuard) which is the global patch guard context.
 */

#pragma once

#include "../Include.hpp"

namespace wsbp {

	/*
	 * I don't know what the fuck does DPC doing in PG Initialization routine.
	 * It just build up DPC and queues on nothing.. wtf??
	 * But the bypass actually works! What the fuck are Microsoft engineers doing?
	 */
	namespace Context7 {

		/*
		 * @brief Fix KiSwInterruptDispatch.
		 * @details KiSwInterruptDispatch derefer global patchguard pointer, 
		 *	which leads to unexpected BSOD. So we just ret patch KiSwInterruptDispatch.
		 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
		 */
		BOOLEAN FixKiSwInterruptDispatch();

		/*
		 * @brief Clears `MaxDataSize` - the global patchguard pointer.
		 * @returns None.
		 */
		VOID ClearMaxDataSizePointer();

		/*
		 * @brief Destroy context 7. It is full bypass of Context7.
		 * @return `TRUE` if operation was successful, `FALSE` otherwise.
		 */
		BOOLEAN DestroyContext7();

	}
}