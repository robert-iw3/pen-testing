/*
 * @file Context7.cpp
 * @brief Implementation of Context7.hpp
 */

#include "Context7.hpp"
#include "../Log.hpp"
#include "../Global.hpp"
#include "../Util/Memory.hpp"

BOOLEAN wsbp::Context7::FixKiSwInterruptDispatch() {

	UCHAR patchBytes[] = {0xC3, 0xCC};
	if (!WriteOnReadOnlyMemory(patchBytes, gl::RtVar::KiSwInterruptDispatchPtr, sizeof(patchBytes))) {
		LogError("FixKiSwInterruptDispatch: Write on Read-Only Memory Failed");
		return FALSE;
	}

	LogInfo("FixKiSwInterruptDispatch: Success");

	return TRUE;
}

VOID wsbp::Context7::ClearMaxDataSizePointer() {

	// It "could" seem to be ULONG variables, according to PDB, but it is actually the pointer variable lmao
	*(uintptr_t*)gl::RtVar::MaxDataSizePtr = NULL;

	LogInfo("ClearMaxDataSizePointer: Success");

	return;
}

BOOLEAN wsbp::Context7::DestroyContext7() {

	if (!FixKiSwInterruptDispatch()) {
		return FALSE;
	}

	ClearMaxDataSizePointer();

	LogInfo("DestroyContext7: Successfully destroyed global PatchGuard pointer");

	return TRUE;
}