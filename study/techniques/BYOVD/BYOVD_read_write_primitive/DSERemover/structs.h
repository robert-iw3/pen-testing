/*
	 Defines all the data structures used across the project
*/

#pragma once

#include <Windows.h>
#include "config.h"

// ***** STRUCTS FOR RTCORE64 READ AND WRITE ***** //

typedef struct RTCORE64_MEMORY_READ {
	BYTE		Pad0[8];
	DWORD64		Address;
	BYTE		Pad1[8];
	DWORD		ReadSize;
	DWORD		Value;
	BYTE		Pad3[16];
} RTCORE64_MEMORY_READ;

typedef struct RTCORE64_MEMORY_WRITE {
	BYTE		Pad0[8];
	DWORD64		Address;
	BYTE		Pad1[8];
	DWORD		WriteSize;
	DWORD		Value;
	BYTE		Pad3[16];
} RTCORE64_MEMORY_WRITE;

// ***** STRUCTS FOR ntoskrnlOffsets.c ***** //

typedef enum CiOffsetType {
	g_CiOptions = 0,
	CiValidateImageHeader,
	_SUPPORTED_CI_OFFSETS_END
} CiOffsetType;

typedef union CiOffsets {
	// structure version of Ci.dll's offsets
	struct {
		DWORD64 g_CiOptions;
		DWORD64 CiValidateImageHeader;
	} st;

	// array version (usefull for code factoring)
	DWORD64 ar[_SUPPORTED_CI_OFFSETS_END];
} CiOffsets;

// ***** STRUCTS FOR DSE.c ***** //

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
	ULONG Length;
	ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemCodeIntegrityInformation = 103
} SYSTEM_INFORMATION_CLASS;