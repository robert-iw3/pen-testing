/*
 * @file Misc.hpp
 * @brief Mitigate Miscellaneous routines that was performed by PatchGuard
 */

#pragma once

#include "../Include.hpp"

namespace wsbp {

	namespace Misc {

		/*
		 * @brief Patch KiMcaDeferredRecoveryService to just return.
		 * @details Additional PatchGuard routine should clear call stacks before you call KeBugCheckEx.
		 * So, all routines that is associated with PatchGuard uses KiMcaDeferredRecoveryService.
		 * We exploit that. Can disable PspProcessDelete, KiInitializeUserApc.
		 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
		 */
		BOOLEAN FixKiMcaDeferredRecoveryServicePtr();
		
		/*
		 * @brief Fix Patchguard Apcs.
		 * @returns `TRUE` if operation was successful.
		 */
		BOOLEAN FixPgApc();

		/*
		 * @brief Fix Patchguard system thread.
		 * @returns `TRUE` if operation was successful.
		 */
		BOOLEAN FixPgSystemThread();

		/*
		 * @brief Disable all miscellaneous routines.
		 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
		 */
		BOOLEAN DisableMiscRoutines();

	}

}