// emu.c
// Core instruction emulation engine
//
// HOW IT WORKS:
// 1. Hardware breakpoints (HWBP) trigger BEFORE the CPU fetches an instruction
// 2. This causes EXCEPTION_SINGLE_STEP exception
// 3. Our VEH catches it and reads the instruction bytes AS DATA (not execution)
// 4. We decode and emulate the instruction in software
// 5. We manually update CPU registers (RIP, RSP, RAX, etc.)
// 6. We set the next HWBP on the new RIP value
// 7. Execution continues - CPU never tries to execute from non-executable memory
//
// WHY THIS BYPASSES DEP/NX:
// - DEP/NX prevents CPU instruction fetch from non-executable pages
// - But it does NOT prevent reading bytes as data
// - Hardware breakpoints trigger BEFORE instruction fetch
// - We read instruction bytes as data, emulate them, update registers
// - CPU never performs the actual instruction fetch from non-executable memory

#include <stdio.h>
#include "emu.h"
#include "debug.h"

// Global state for tracking what we're emulating
void* g_codeAddress = NULL;
SIZE_T g_codeSize = 0;
int    g_instructionCount = 0;

// Helper to configure hardware breakpoint registers
// DR0 = address to watch
// DR7 = control register (bit 0 = enable DR0, bits configure as execute breakpoint)
static __forceinline void SetHWBPInContext(CONTEXT* ctx, void* address) {
    ctx->Dr0 = (DWORD64)address;
    // DR7 = 0x1: Enable DR0, Type = Execute (00), Length = 1 byte
    // Bit layout: [LEN3][RW3][LEN2][RW2][LEN1][RW1][LEN0][RW0][G3][L3][G2][L2][G1][L1][G0][L0]
    // We set L0=1 (local enable for DR0)
    ctx->Dr7 = 0x1ull;
}

// Public interface to set hardware breakpoint
void SetHWBP(EXCEPTION_POINTERS* exceptionInfo, void* address) {
    SetHWBPInContext(exceptionInfo->ContextRecord, address);
}

// Public interface to clear hardware breakpoint
void ClearHWBP(EXCEPTION_POINTERS* exceptionInfo) {
    exceptionInfo->ContextRecord->Dr0 = 0;
    exceptionInfo->ContextRecord->Dr7 = 0;
}

// ============================================================================
// INSTRUCTION EMULATOR
// ============================================================================
// This is the heart of the technique. For each instruction in our RW buffer:
// 1. Read the opcode byte (as data - this is allowed even for non-executable memory)
// 2. Decode what the instruction does
// 3. Manually update CPU registers to simulate the instruction's effect
// 4. Update RIP to point to the next instruction
//
// Currently implements only:
// - 0x90 (NOP) - No operation
// - 0xC3 (RET) - Return from function
//
// For real shellcode, you'd need to implement hundreds of instructions:
// - MOV, PUSH, POP, CALL, JMP, ADD, SUB, XOR, etc.
// - Memory addressing modes
// - Segment prefixes (GS:, FS:)
// - REX prefixes for 64-bit operations
// ============================================================================
BOOL EmulateInstruction(EXCEPTION_POINTERS* exceptionInfo, unsigned char* address) {
    // Read the opcode byte AS DATA (not as an instruction)
    // This is the key: we're reading bytes, not executing them
    unsigned char opcode = *address;
    printf("  [Emulate] RIP=%p Opcode=0x%02X\n",
        (void*)exceptionInfo->ContextRecord->Rip, opcode);

    switch (opcode) {
    case 0x90: // NOP (No Operation)
        // NOP does nothing except advance RIP by 1 byte
        exceptionInfo->ContextRecord->Rip += 1;
        return TRUE;

    case 0xC3: // RET (Return from function)
    {
        // RET pops return address from stack and jumps to it
        // 1. Read return address from stack (pointed to by RSP)
        DWORD64 ret = *(DWORD64*)(exceptionInfo->ContextRecord->Rsp);
        printf("  [Emulate] RET to %p\n", (void*)ret);

        // 2. Update RIP to return address
        exceptionInfo->ContextRecord->Rip = ret;

        // 3. Pop stack (RSP += 8 on x64)
        exceptionInfo->ContextRecord->Rsp += 8;
        return TRUE;
    }

    default:
        // Unsupported instruction - we can't continue emulation
        printf("  [Emulate] Unsupported opcode 0x%02X\n", opcode);
        return FALSE;
    }
}

// ============================================================================
// VECTORED EXCEPTION HANDLER
// ============================================================================
// This function is called by Windows whenever an exception occurs anywhere
// in the process. We're specifically looking for EXCEPTION_SINGLE_STEP,
// which is triggered by hardware breakpoints.
//
// EXECUTION FLOW:
// 1. Program calls into our RW buffer (demo_code)
// 2. CPU tries to fetch instruction from RIP
// 3. BEFORE fetch happens, hardware breakpoint triggers
// 4. Windows generates EXCEPTION_SINGLE_STEP
// 5. Windows calls our VEH (this function)
// 6. We emulate the instruction
// 7. We set next hardware breakpoint
// 8. We return EXCEPTION_CONTINUE_EXECUTION
// 9. CPU resumes at the NEW RIP we set
// 10. Repeat from step 2 until code exits our buffer
// ============================================================================
LONG WINAPI MyExceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {
    DWORD code = exceptionInfo->ExceptionRecord->ExceptionCode;

    // Only handle EXCEPTION_SINGLE_STEP (0x80000004)
    // This is triggered by:
    // - Hardware breakpoints (DR0-DR3)
    // - Single-step debugging (Trap Flag in EFLAGS)
    if (code == EXCEPTION_SINGLE_STEP) {
        DWORD64 rip = exceptionInfo->ContextRecord->Rip;
        printf("\n[VEH] SINGLE_STEP at RIP=%p\n", (void*)rip);

        // Check if exception occurred within our code buffer
        // This prevents us from accidentally emulating random code elsewhere
        if (rip >= (DWORD64)g_codeAddress &&
            rip < (DWORD64)g_codeAddress + g_codeSize) {

            g_instructionCount++;

            // Emulate the instruction at current RIP
            if (!EmulateInstruction(exceptionInfo, (unsigned char*)rip)) {
                // Emulation failed (unsupported instruction)
                // Clear hardware breakpoint and let exception propagate
                ClearHWBP(exceptionInfo);
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // After emulation, RIP has been updated to next instruction
            // If still inside our buffer, set hardware breakpoint on next instruction
            if (exceptionInfo->ContextRecord->Rip >= (DWORD64)g_codeAddress &&
                exceptionInfo->ContextRecord->Rip < (DWORD64)g_codeAddress + g_codeSize) {

                // Set HWBP on next instruction
                // This creates a chain: HWBP -> Emulate -> Set next HWBP -> ...
                SetHWBP(exceptionInfo, (void*)exceptionInfo->ContextRecord->Rip);
            }
            else {
                // We've left the code buffer (e.g., after RET)
                // Clear the hardware breakpoint
                ClearHWBP(exceptionInfo);
            }

            // Tell Windows to continue execution with modified context
            // CPU will resume at the RIP we set during emulation
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // Not our exception - let Windows handle it
    return EXCEPTION_CONTINUE_SEARCH;
}