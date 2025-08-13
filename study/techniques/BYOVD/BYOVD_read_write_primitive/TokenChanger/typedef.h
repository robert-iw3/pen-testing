/*
	 Defines all the typedef definitions used across the project
*/

#pragma once

#include <Windows.h>
#include "config.h"

// ***** TYPEDEF FOR token.c ***** //
// Function pointer to RtlGetVersion
typedef NTSTATUS(NTAPI* fnRtlGetVersion)(
	PRTL_OSVERSIONINFOW lpVersionInformation
);

// ***** TYPEDEF FOR process.c ***** //
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);