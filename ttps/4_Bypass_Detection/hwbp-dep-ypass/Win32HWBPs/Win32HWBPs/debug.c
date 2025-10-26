// debug.c
// Implementation of debugging utilities
#define _CRT_SECURE_NO_WARNINGS
#include "debug.h"

// Disable buffering so printf() output appears immediately
void UnbufferStdout(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
}

// Interactive pause point for debugging
void DBG_Pause(const char* msg) {
    printf("\n[DBG] %s  (press Enter to continue)\n", msg);
    getchar();
}

// Display all important CPU registers in readable format
void PRINT_CONTEXT(const CONTEXT* c) {
    printf("---- CONTEXT ----\n");
    printf("RAX=%016llx  RBX=%016llx  RCX=%016llx  RDX=%016llx\n",
        c->Rax, c->Rbx, c->Rcx, c->Rdx);
    printf("RSI=%016llx  RDI=%016llx  RBP=%016llx  RSP=%016llx\n",
        c->Rsi, c->Rdi, c->Rbp, c->Rsp);
    // RIP = Instruction Pointer (where CPU thinks it's executing)
    printf("RIP=%016llx  EFLAGS=%08lx\n", c->Rip, c->EFlags);
    // DR0 = Debug Register 0 (hardware breakpoint address)
    // DR7 = Debug Register 7 (hardware breakpoint control)
    printf("DR0=%016llx  DR7=%016llx\n", c->Dr0, c->Dr7);
    printf("-----------------\n");
}

// Query and display memory region properties
void DUMP_REGION(void* p) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery(p, &mbi, sizeof(mbi))) {
        printf("---- MEM REGION @ %p ----\n", p);
        printf(" BaseAddress   : %p\n", mbi.BaseAddress);
        printf(" RegionSize    : 0x%Ix\n", mbi.RegionSize);
        // Protect shows if memory is RW, RX, RWX, etc.
        // PAGE_READWRITE = RW (non-executable, NX bit set)
        printf(" Protect       : 0x%lx\n", mbi.Protect);
        printf("-------------------------\n");
    }
}

// Hexdump bytes from memory
void DUMP_BYTES(const void* p, SIZE_T len) {
    const unsigned char* b = (const unsigned char*)p;
    printf("---- BYTES @ %p (len=%zu) ----\n", p, (size_t)len);
    for (SIZE_T i = 0; i < len; i++) {
        if (i % 16 == 0) printf("%p : ", b + i);
        printf("%02X ", b[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
    printf("-------------------------------\n");
}