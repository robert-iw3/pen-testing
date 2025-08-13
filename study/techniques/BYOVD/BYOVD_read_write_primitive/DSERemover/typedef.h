/*
	 Defines all the typedef definitions used across the project
*/

#pragma once

#include <Windows.h>
#include "config.h"

// ***** TYPEDEF FOR DSE.c ***** //
// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);