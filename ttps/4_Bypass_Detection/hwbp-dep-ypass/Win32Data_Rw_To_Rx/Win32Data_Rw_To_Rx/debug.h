#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <windows.h>

// Color codes for console output (optional but nice for screenshots)
#define COLOR_RESET   ""
#define COLOR_GREEN   ""
#define COLOR_YELLOW  ""
#define COLOR_CYAN    ""
#define COLOR_RED     ""

// Function declarations
void start_debug_session(const char* message);
void show_initial_memory_state(unsigned char* shellcode, size_t size);
void show_memory_protection_change(unsigned char* shellcode, size_t size);
void show_execution_point(unsigned char* shellcode);
void show_execution_complete();
void dump_memory_region(void* address);
void dump_shellcode_bytes(unsigned char* shellcode, size_t size);
void pause_for_debugger(const char* message);

#endif // DEBUG_H