#include "Memory.h"

BOOLEAN WriteOnReadOnlyMemory(PVOID src, PVOID dst, size_t size) {

	PMDL mdl = NULL;

	if (size == 0) return TRUE;
	mdl = IoAllocateMdl(dst, (ULONG)size, FALSE, FALSE, NULL);

	if (mdl == NULL) {
		return FALSE;
	}

	PVOID mapped = NULL;
	BOOLEAN success = FALSE;

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

		if (mapped == NULL) {
			__leave;
		}

		MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
		RtlCopyMemory(mapped, src, size);

		success = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		success = FALSE;
	}

	if (mapped != NULL) {
		MmUnmapLockedPages(mapped, mdl);
	}

	if (mdl != NULL) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}

	return success;
}



BOOLEAN HookTrampoline(PVOID origFunction, PVOID hookFunction, PVOID gateway, size_t len) {

	UCHAR detourTemplate[] = {
		0xFF, 0x25, 0, 0, 0, 0
	};

	if (len < sizeof(detourTemplate) + 8) {
		return FALSE;
	}

	if (!WriteOnReadOnlyMemory(origFunction, gateway, len)) {
		return FALSE;
	}

	if (!WriteOnReadOnlyMemory(detourTemplate, (PVOID)((uintptr_t)gateway + len), sizeof(detourTemplate))) {
		return FALSE;
	}

	uintptr_t returnAddress = (uintptr_t)origFunction + len;
	if (!WriteOnReadOnlyMemory(&returnAddress, (PVOID)((uintptr_t)gateway + len + sizeof(detourTemplate)), 8)) {
		return FALSE;
	}

	if (!WriteOnReadOnlyMemory(detourTemplate, origFunction, sizeof(detourTemplate))) {
		return FALSE;
	}

	uintptr_t detourAddress = (uintptr_t)hookFunction;
	if (!WriteOnReadOnlyMemory(&detourAddress, (PVOID)((uintptr_t)origFunction + sizeof(detourTemplate)), 8)) {
		return FALSE;
	}

	// So, the gateway is like this:
	// .. (original code) .. | jmp [rip+0x00] | Orig.

	// And the original function is like this:
	// jmp [rip+0x00] | Hook

	return TRUE;
}