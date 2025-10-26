#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <windows.h>

// Function declarations for failure demonstration
void start_debug_session_failure(const char* message);
void show_nonexecutable_memory_state(unsigned char* shellcode, size_t size);
void explain_expected_crash(unsigned char* shellcode);
void prepare_for_crash();
void show_crash_analysis(DWORD exceptionCode, unsigned char* shellcode);
void show_failure_summary();

// Helper functions
void dump_memory_region_failure(void* address);
void dump_shellcode_bytes_failure(unsigned char* shellcode, size_t size);

#endif // DEBUG_H