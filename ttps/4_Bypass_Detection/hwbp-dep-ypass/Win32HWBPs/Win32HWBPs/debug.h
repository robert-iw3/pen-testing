// debug.h
// Helper utilities for debugging and visualization
#pragma once
#include <windows.h>
#include <stdio.h>

// Disable stdout buffering for immediate output
void UnbufferStdout(void);

// Pause execution with a message (waits for Enter key)
void DBG_Pause(const char* msg);

// Print all important CPU register values from a CONTEXT structure
void PRINT_CONTEXT(const CONTEXT* c);

// Display memory region information (address, size, protection flags)
void DUMP_REGION(void* p);

// Hexdump a memory region
void DUMP_BYTES(const void* p, SIZE_T len);