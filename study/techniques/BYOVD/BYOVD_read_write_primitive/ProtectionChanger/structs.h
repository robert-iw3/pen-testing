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

// ***** STRUCTS FOR protection.c ***** //

typedef struct _Offsets{
	DWORD64 UniqueProcessIdOffset;
	DWORD64 ActiveProcessLinksOffset;
	DWORD64 ProtectionOffset;
} Offsets;