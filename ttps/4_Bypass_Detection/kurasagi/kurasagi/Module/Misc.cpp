/*
 * @file Misc.cpp
 * @brief Implementation of Misc.hpp
 */

#include "Misc.hpp"
#include "../Log.hpp"
#include "../Util/Memory.hpp"
#include "../Global.hpp"

BOOLEAN wsbp::Misc::FixKiMcaDeferredRecoveryServicePtr() {

	UCHAR patchBytes[] = { 0xC3, 0xCC };
	if (!WriteOnReadOnlyMemory(patchBytes, gl::RtVar::KiMcaDeferredRecoveryServicePtr, sizeof(patchBytes))) {
		LogInfo("FixKiMcaDeferredRecoveryServicePtr: Couldn't write on read only memory");
		return FALSE;
	}

	LogInfo("FixKiMcaDeferredRecoveryServicePtr: Success");
	
	return TRUE;
}

BOOLEAN wsbp::Misc::DisableMiscRoutines() {

	if (!FixKiMcaDeferredRecoveryServicePtr()) {
		return FALSE;
	}

	if (!FixPgApc()) {
		return FALSE;
	}

	if (!FixPgSystemThread()) {
		return FALSE;
	}

	LogInfo("DisableMiscRoutines: Miscellaneous routines are all disabled.");

	return TRUE;
}

BOOLEAN wsbp::Misc::FixPgApc() {
	// Deprecated, moved to Barricade. Because it just uses SO MUCH RESOURCES
	return TRUE;
}

BOOLEAN wsbp::Misc::FixPgSystemThread() {
	// Deprecated, moved to Barricade. Because it just uses SO MUCH RESOURCES
	return TRUE;
}