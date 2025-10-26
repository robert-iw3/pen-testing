// main.c
// Demonstration of hardware breakpoint-based code execution from RW memory
//
// TECHNIQUE OVERVIEW:
// -------------------
// This program demonstrates executing code from non-executable memory by
// using hardware breakpoints and instruction emulation. This bypasses
// Data Execution Prevention (DEP) / NX (No-eXecute) protection.
//
// NORMAL EXECUTION (with executable memory):
// 1. Code is in RX (Read+Execute) or RWX memory
// 2. CPU fetches instruction from RIP
// 3. CPU decodes and executes instruction
// 4. RIP advances to next instruction
// 5. Repeat
//
// THIS TECHNIQUE (with non-executable memory):
// 1. Code is in RW (Read+Write) memory - NOT EXECUTABLE
// 2. Hardware breakpoint set on RIP
// 3. CPU attempts to fetch instruction
// 4. Hardware breakpoint triggers BEFORE fetch completes
// 5. EXCEPTION_SINGLE_STEP exception occurs
// 6. Our VEH catches exception
// 7. We read instruction bytes AS DATA (allowed because memory is readable)
// 8. We emulate instruction effect (update registers)
// 9. We set next hardware breakpoint
// 10. We return EXCEPTION_CONTINUE_EXECUTION
// 11. CPU resumes at NEW RIP (that we set)
// 12. Repeat from step 3
//
// KEY INSIGHT:
// ------------
// - DEP/NX prevents CPU from EXECUTING code from non-executable memory
// - But it does NOT prevent READING bytes from that memory as data
// - Hardware breakpoints trigger BEFORE the CPU tries to execute
// - We read the instruction bytes as data, emulate their behavior,
//   and manually update the CPU state
// - The CPU never actually tries to fetch instructions from non-executable memory
//
// WHY THIS MATTERS:
// -----------------
// This technique can be used by malware to:
// 1. Store shellcode in non-executable memory (bypasses memory scanners)
// 2. Execute shellcode without marking pages as executable (bypasses DEP/NX)
// 3. Evade signature-based detection (code never exists in executable memory)
//
// LIMITATIONS:
// ------------
// 1. Requires implementing a full x86-64 emulator (complex)
// 2. Only 4 hardware breakpoints available (DR0-DR3)
// 3. Can be detected by monitoring debug register usage
// 4. Very slow compared to native execution (thousands of times slower)

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include "debug.h"
#include "emu.h"

// ============================================================
// CODE BUFFER
// ============================================================
// This buffer contains our "shellcode" (5 NOPs + RET)
// It's stored in the .data section, which is RW (not executable)
//
// __declspec(align(16)) ensures proper alignment
// This is NOT in executable memory - you can verify with Process Hacker:
// - Right-click process -> Properties -> Memory
// - Find this address - it will show PAGE_READWRITE, not PAGE_EXECUTE_*
// ============================================================
__declspec(align(16)) unsigned char demo_code[] = {
    0x90,  // NOP
    0x90,  // NOP
    0x90,  // NOP
    0x90,  // NOP
    0x90,  // NOP
    0xC3   // RET
};

// Initialize emulator globals to point to our code buffer
static void InitializeCodeSection(void) {
    g_codeAddress = demo_code;
    g_codeSize = sizeof(demo_code);
}

// ============================================================
// MAIN EXECUTION FLOW
// ============================================================
int main() {
    UnbufferStdout();
    printf("=== HWBP + Instruction Emulation Demo (Static RW Section) ===\n\n");

    // ---------------------------------------------------------------
    // STEP 1: Initialize code buffer
    // ---------------------------------------------------------------
    InitializeCodeSection();

    // Display memory region info - you'll see PAGE_READWRITE (0x04)
    // NOT PAGE_EXECUTE_READWRITE (0x40)
    DUMP_REGION(g_codeAddress);

    // Show the actual bytes we'll be "executing"
    DUMP_BYTES(g_codeAddress, g_codeSize);

    DBG_Pause("Attach debugger now before installing VEH");

    // ---------------------------------------------------------------
    // STEP 2: Install Vectored Exception Handler
    // ---------------------------------------------------------------
    // VEH is called FIRST when an exception occurs (before SEH)
    // Our handler will intercept EXCEPTION_SINGLE_STEP from hardware breakpoints
    PVOID handler = AddVectoredExceptionHandler(1, MyExceptionHandler);
    if (!handler) {
        printf("[!] Failed to install VEH\n");
        return 1;
    }
    printf("[+] VEH installed at %p\n", handler);

    DBG_Pause("VEH installed — set breakpoints now");

    // ---------------------------------------------------------------
    // STEP 3: Arm hardware breakpoint on first instruction
    // ---------------------------------------------------------------
    // We set DR0 to point to our code buffer
    // We set DR7 to enable DR0 as an execute breakpoint
    //
    // When the CPU tries to execute the first instruction:
    // 1. Hardware breakpoint triggers
    // 2. EXCEPTION_SINGLE_STEP occurs
    // 3. Our VEH catches it
    // 4. We emulate the instruction
    // 5. We set the next hardware breakpoint
    // 6. Loop continues
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    // Set hardware breakpoint on first byte of code
    ctx.Dr0 = (DWORD64)g_codeAddress;

    // DR7 controls hardware breakpoints
    // 0x1 = Enable DR0 (bit 0), Local to this thread
    // Type = Execute breakpoint (00)
    // Length = 1 byte
	// ull means "unsigned long long" to ensure 64-bit constant
    ctx.Dr7 = 0x1ull;

    SetThreadContext(GetCurrentThread(), &ctx);

    PRINT_CONTEXT(&ctx);
    DBG_Pause("HWBPs armed — ready to execute");

    // ---------------------------------------------------------------
    // STEP 4: "Execute" the code
    // ---------------------------------------------------------------
    // We cast our RW buffer to a function pointer and call it
    //
    // WHAT REALLY HAPPENS:
    // 1. CALL instruction pushes return address and sets RIP to demo_code
    // 2. CPU attempts to fetch instruction from demo_code
    // 3. Hardware breakpoint triggers BEFORE fetch
    // 4. EXCEPTION_SINGLE_STEP occurs
    // 5. Our VEH emulates the instruction (NOP)
    // 6. VEH sets next HWBP and returns EXCEPTION_CONTINUE_EXECUTION
    // 7. CPU resumes at new RIP (demo_code + 1)
    // 8. Repeat for all 6 instructions
    // 9. Final RET instruction pops return address and jumps back to main()
    //
    // CRITICAL: The CPU never actually executes an instruction from demo_code!
    // Every single instruction is intercepted and emulated.
    printf("\n[*] Calling demo_code at %p ...\n", g_codeAddress);
    typedef void (*func_t)(void);
    func_t f = (func_t)g_codeAddress;

    __try {
        f();  // This looks like a normal function call, but it's emulated!
        printf("[+] Returned cleanly from emulated code\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[!] Exception: 0x%08lx\n", GetExceptionCode());
    }

    // ---------------------------------------------------------------
    // STEP 5: Summary
    // ---------------------------------------------------------------
    printf("\n[Summary]\n");
    printf("  Emulated instructions: %d\n", g_instructionCount);
    printf("  Memory protection: RW (no VirtualProtect)\n");
    printf("\n");
    printf("  What happened:\n");
    printf("  - Code was stored in non-executable memory\n");
    printf("  - Hardware breakpoints intercepted each instruction\n");
    printf("  - Instructions were emulated in software\n");
    printf("  - CPU never fetched instructions from non-executable memory\n");
    printf("  - DEP/NX was completely bypassed\n");

    DBG_Pause("Press Enter to exit");

    RemoveVectoredExceptionHandler(handler);
    return 0;
}