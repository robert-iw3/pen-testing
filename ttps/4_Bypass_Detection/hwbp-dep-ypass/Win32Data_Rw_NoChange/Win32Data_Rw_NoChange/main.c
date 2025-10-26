/* Windows Loader - INTENTIONAL FAILURE DEMONSTRATION
 *
 * PURPOSE:
 * - Demonstrates what happens when you try to execute code from non-executable memory
 * - Shows the protection mechanism (DEP/NX) in action
 * - This code will CRASH with EXCEPTION_ACCESS_VIOLATION (0xC0000005)
 *
 * WHAT THIS SHOWS:
 * - Shellcode is stored in .data section (PAGE_READWRITE by default)
 * - NO VirtualProtect call to make it executable
 * - Attempted execution triggers access violation
 * - This is WHY techniques like VirtualProtect or hardware breakpoints are needed
 */

 /* Ethical Use Disclaimer:
  * For educational use only in controlled environments.
  * Unauthorized real-world use may breach laws and ethics.
  * Obtain explicit permission before testing or deploying.
  */

  /* Author:
   * @VirtualAllocEx
   */

   // Uncomment to enable debug mode
#define DEBUG_MODE

#include <stdio.h>
#include <windows.h>

#ifdef DEBUG_MODE
#include "debug.h"
#endif

// Simple shellcode: 5 NOPs + RET
// This is stored in the .data section (PAGE_READWRITE - NOT EXECUTABLE)
unsigned char shellcode[] = {
    0x90,  // NOP
    0x90,  // NOP
    0x90,  // NOP
    0x90,  // NOP
    0x90,  // NOP
    0xC3   // RET
};

int main() {

#ifdef DEBUG_MODE
    // STEP 0: Start debugging session
    start_debug_session_failure("Press <ENTER> to start the FAILURE demonstration.");

    // STEP 1: Show initial memory state (RW, non-executable)
    show_nonexecutable_memory_state(shellcode, sizeof(shellcode));

    // STEP 2: Explain what will happen
    explain_expected_crash(shellcode);

    // STEP 3: Prepare for crash
    prepare_for_crash();
#endif

    // Try to execute shellcode WITHOUT changing memory protection
    // This will cause EXCEPTION_ACCESS_VIOLATION (0xC0000005)
    printf("\n[>>>] Attempting to execute from non-executable memory...\n\n");

    __try {
        // This will crash!
        ((void(*)())shellcode)();

        // This line will NEVER be reached
        printf("[+] Execution succeeded (This should not print!)\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception handler catches the access violation
        DWORD exceptionCode = GetExceptionCode();

#ifdef DEBUG_MODE
        show_crash_analysis(exceptionCode, shellcode);
#else
        printf("\n[!] EXCEPTION CAUGHT!\n");
        printf("    Exception Code: 0x%08lX\n", exceptionCode);
        if (exceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            printf("    Exception Name: EXCEPTION_ACCESS_VIOLATION\n");
            printf("    Reason: Attempted to execute non-executable memory\n");
        }
#endif
    }

#ifdef DEBUG_MODE
    show_failure_summary();
#endif

    return 0;
}