// emu.h
// Instruction emulation engine interface
#pragma once
#include <windows.h>

// Global state tracking
extern void* g_codeAddress;      // Start of code buffer being emulated
extern SIZE_T g_codeSize;        // Size of code buffer
extern int g_instructionCount;   // Number of instructions emulated

// Set hardware breakpoint on specific address
void SetHWBP(EXCEPTION_POINTERS* exceptionInfo, void* address);

// Clear hardware breakpoint
void ClearHWBP(EXCEPTION_POINTERS* exceptionInfo);

// Emulate a single x86-64 instruction at given address
BOOL EmulateInstruction(EXCEPTION_POINTERS* exceptionInfo, unsigned char* address);

// Vectored Exception Handler - catches hardware breakpoint triggers
LONG WINAPI MyExceptionHandler(EXCEPTION_POINTERS* exceptionInfo);