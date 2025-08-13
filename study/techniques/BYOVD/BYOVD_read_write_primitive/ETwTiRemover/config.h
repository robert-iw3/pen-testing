/*
		Store all variables and settings used across the project
*/

#pragma once

// Define path for the driver file
#define g_VULNDRIVERPATH	L"\\System32\\Drivers\\"		// Default runtime-loaded kernel drivers

// Define variables for the vulnerable driver
#define g_VULNDRIVERNAME		L"RTCORE"
#define g_VULNDRIVERFILENAME	L"RTCore64.sys"
#define g_VULNDRIVERSYMLINK		L"\\\\.\\RTCore64"

// Define IOCTL codes
#define RTCORE64_MEMORY_READ_CODE	0x80002048
#define RTCORE64_MEMORY_WRITE_CODE	0x8000204C