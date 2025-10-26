/* Windows Loader Overview:
 * - Stores the shellcode in the .data section of the PE file.
 * - Changes memory protection of the .data section to PAGE_EXECUTE_READ using VirtualProtect.
 * - Executes the shellcode directly from the .data section.
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
// This is stored in the .data section (non-executable by default)
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
    start_debug_session("Press <ENTER> to start the debugging session.");

    // STEP 1: Show initial memory state (RW, non-executable)
    show_initial_memory_state(shellcode, sizeof(shellcode));

    // STEP 2: Change memory protection to executable
    show_memory_protection_change(shellcode, sizeof(shellcode));

    // STEP 3: Execute shellcode
    show_execution_point(shellcode);
#else
    // Non-debug mode: just change protection
    DWORD oldProtect = 0;
    VirtualProtect(shellcode, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect);
#endif

    // Execute the shellcode
    // This casts the byte array to a function pointer and calls it
    ((void(*)())shellcode)();

#ifdef DEBUG_MODE
    // STEP 4: Show completion
    show_execution_complete();
#endif

    return 0;
}