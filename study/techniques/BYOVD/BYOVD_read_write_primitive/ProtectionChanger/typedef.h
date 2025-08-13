/*
	 Defines all the typedef definitions used across the project
*/

#pragma once

#include <Windows.h>
#include "config.h"

// ***** TYPEDEF FOR protection.c ***** //
// Function pointer to RtlGetVersion
typedef NTSTATUS(NTAPI* fnRtlGetVersion)(
	PRTL_OSVERSIONINFOW lpVersionInformation
	);