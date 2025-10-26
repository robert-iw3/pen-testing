#include "debug.h"

// Disable stdout buffering for immediate output
static void ensure_unbuffered_output() {
    setvbuf(stdout, NULL, _IONBF, 0);
}

// Helper to get memory protection as string
static const char* protection_to_string(DWORD protect) {
    switch (protect) {
    case PAGE_NOACCESS:          return "PAGE_NOACCESS (0x01)";
    case PAGE_READONLY:          return "PAGE_READONLY (0x02)";
    case PAGE_READWRITE:         return "PAGE_READWRITE (0x04)";
    case PAGE_WRITECOPY:         return "PAGE_WRITECOPY (0x08)";
    case PAGE_EXECUTE:           return "PAGE_EXECUTE (0x10)";
    case PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ (0x20)";
    case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE (0x40)";
    case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY (0x80)";
    default:                     return "UNKNOWN";
    }
}

// Helper to print separator line
static void print_separator(char c) {
    for (int i = 0; i < 80; i++) putchar(c);
    putchar('\n');
}

void start_debug_session(const char* message) {
    ensure_unbuffered_output();
    print_separator('=');
    printf("  STEP-BY-STEP DEBUGGING SESSION\n");
    printf("  VirtualProtect Method: .data Section Execution\n");
    print_separator('=');
    printf("\n[#] %s\n", message);
    (void)getchar();
}

void show_initial_memory_state(unsigned char* shellcode, size_t size) {
    print_separator('-');
    printf("STEP 1: INITIAL MEMORY STATE\n");
    print_separator('-');

    printf("\n[+] Shellcode location:\n");
    printf("    Base address: 0x%p\n", (void*)shellcode);
    printf("    Size: %zu bytes (0x%zX)\n", size, size);

    // Query memory information
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery(shellcode, &mbi, sizeof(mbi))) {
        printf("\n[+] Memory region information:\n");
        printf("    BaseAddress:       0x%p\n", mbi.BaseAddress);
        printf("    AllocationBase:    0x%p\n", mbi.AllocationBase);
        printf("    RegionSize:        0x%IX (%zu bytes)\n", mbi.RegionSize, (size_t)mbi.RegionSize);
        printf("    State:             0x%08lX ", mbi.State);
        if (mbi.State == MEM_COMMIT) printf("(MEM_COMMIT)\n");
        else if (mbi.State == MEM_RESERVE) printf("(MEM_RESERVE)\n");
        else printf("(OTHER)\n");

        printf("    Protect:           0x%08lX (%s)\n",
            mbi.Protect, protection_to_string(mbi.Protect));
        printf("    Type:              0x%08lX ", mbi.Type);
        if (mbi.Type == MEM_IMAGE) printf("(MEM_IMAGE - PE section)\n");
        else if (mbi.Type == MEM_MAPPED) printf("(MEM_MAPPED)\n");
        else if (mbi.Type == MEM_PRIVATE) printf("(MEM_PRIVATE)\n");
        else printf("(OTHER)\n");
    }

    printf("\n[!] CRITICAL OBSERVATION:\n");
    printf("    Current protection: PAGE_READWRITE (0x04)\n");
    printf("    NX bit status: ENABLED (Non-executable)\n");
    printf("    Can read?  YES\n");
    printf("    Can write? YES\n");
    printf("    Can execute? NO ❌\n");

    printf("\n[#] Shellcode bytes:\n");
    dump_shellcode_bytes(shellcode, size);

    printf("\n[#] If we tried to execute now, we would get:\n");
    printf("    Exception: 0xC0000005 (EXCEPTION_ACCESS_VIOLATION)\n");
    printf("    Reason: Attempted to execute non-executable memory\n");

    printf("\n[#] Press <ENTER> to continue to next step...\n");
    (void)getchar();
}

void show_memory_protection_change(unsigned char* shellcode, size_t size) {
    print_separator('-');
    printf("STEP 2: CHANGING MEMORY PROTECTION\n");
    print_separator('-');

    printf("\n[*] Calling VirtualProtect()...\n");
    printf("    Address: 0x%p\n", (void*)shellcode);
    printf("    Size: %zu bytes\n", size);
    printf("    NewProtect: PAGE_EXECUTE_READ (0x20)\n");

    DWORD oldProtect = 0;
    BOOL result = VirtualProtect(shellcode, size, PAGE_EXECUTE_READ, &oldProtect);

    if (result) {
        printf("\n[+] VirtualProtect() succeeded!\n");
        printf("    Old protection: 0x%08lX (%s)\n",
            oldProtect, protection_to_string(oldProtect));
        printf("    New protection: 0x%08lX (%s)\n",
            PAGE_EXECUTE_READ, protection_to_string(PAGE_EXECUTE_READ));
    }
    else {
        printf("\n[!] VirtualProtect() FAILED!\n");
        printf("    Error code: %lu\n", GetLastError());
        return;
    }

    // Verify the change
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery(shellcode, &mbi, sizeof(mbi))) {
        printf("\n[+] Verified new memory state:\n");
        printf("    Current protection: 0x%08lX (%s)\n",
            mbi.Protect, protection_to_string(mbi.Protect));
    }

    printf("\n[!] CRITICAL CHANGE:\n");
    printf("    BEFORE: PAGE_READWRITE (RW-)\n");
    printf("    AFTER:  PAGE_EXECUTE_READ (R-X)\n");
    printf("\n");
    printf("    Can read?  YES\n");
    printf("    Can write? NO\n");
    printf("    Can execute? YES ✅\n");

    printf("\n[*] The NX (No-eXecute) bit has been DISABLED for this page\n");
    printf("[*] CPU can now fetch and execute instructions from this memory\n");

    printf("\n[#] Press <ENTER> to execute the shellcode...\n");
    (void)getchar();
}

void show_execution_point(unsigned char* shellcode) {
    print_separator('-');
    printf("STEP 3: EXECUTING SHELLCODE\n");
    print_separator('-');

    printf("\n[*] About to transfer execution to shellcode...\n");
    printf("    Target address: 0x%p\n", (void*)shellcode);
    printf("    First instruction: 0x%02X (NOP)\n", shellcode[0]);

    printf("\n[*] Execution flow:\n");
    printf("    1. CALL instruction pushes return address to stack\n");
    printf("    2. RIP is set to 0x%p\n", (void*)shellcode);
    printf("    3. CPU fetches instruction from RIP\n");
    printf("    4. MMU checks memory protection\n");
    printf("    5. Protection is PAGE_EXECUTE_READ → ALLOWED ✅\n");
    printf("    6. CPU executes: NOP, NOP, NOP, NOP, NOP, RET\n");
    printf("    7. RET instruction pops return address and returns here\n");

    printf("\n[!] ATTACH DEBUGGER NOW:\n");
    printf("    Process ID: %lu\n", GetCurrentProcessId());
    printf("    Breakpoint address: 0x%p\n", (void*)shellcode);
    printf("    Command: bp 0x%p\n", (void*)shellcode);

    printf("\n[#] Press <ENTER> when ready to execute...\n");
    (void)getchar();

    printf("\n[>>>] Executing shellcode NOW...\n\n");
}

void show_execution_complete() {
    printf("\n[<<<] Returned from shellcode successfully!\n");

    print_separator('-');
    printf("STEP 4: EXECUTION COMPLETED\n");
    print_separator('-');

    printf("\n[+] Shellcode execution completed without errors\n");
    printf("[+] Control flow returned normally via RET instruction\n");

    printf("\n[*] What happened:\n");
    printf("    ✓ Memory was marked executable (PAGE_EXECUTE_READ)\n");
    printf("    ✓ CPU successfully fetched instructions from .data section\n");
    printf("    ✓ All 5 NOP instructions executed\n");
    printf("    ✓ RET instruction returned control to main()\n");
    printf("    ✓ No exceptions occurred\n");

    printf("\n[*] This is the TRADITIONAL method of shellcode execution\n");
    printf("    Detection surface:\n");
    printf("    - VirtualProtect() API call → Monitored by EDR/AV\n");
    printf("    - Memory page marked executable → Memory scanner detection\n");
    printf("    - Executable code in .data section → Anomalous behavior\n");

    print_separator('=');
    printf("DEBUG SESSION COMPLETED\n");
    print_separator('=');

    printf("\n[#] Press <ENTER> to exit...\n");
    (void)getchar();
}

void dump_shellcode_bytes(unsigned char* shellcode, size_t size) {
    printf("    Offset  Bytes                                            ASCII\n");
    printf("    ------  -----------------------------------------------  ----------------\n");

    for (size_t i = 0; i < size; i += 16) {
        printf("    0x%04zX  ", i);

        // Hex dump
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02X ", shellcode[i + j]);
            }
            else {
                printf("   ");
            }
        }

        printf(" ");

        // ASCII dump
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = shellcode[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }

        // Instruction comments for known opcodes
        if (i == 0) {
            printf("  ; NOP instructions");
        }
        else if (i + 5 < size && shellcode[i] == 0xC3) {
            printf("  ; RET");
        }

        printf("\n");
    }
}

void dump_memory_region(void* address) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        printf("\n[Memory Region @ 0x%p]\n", address);
        printf("  BaseAddress:    0x%p\n", mbi.BaseAddress);
        printf("  RegionSize:     0x%IX\n", mbi.RegionSize);
        printf("  State:          0x%08lX\n", mbi.State);
        printf("  Protect:        0x%08lX (%s)\n",
            mbi.Protect, protection_to_string(mbi.Protect));
        printf("  Type:           0x%08lX\n", mbi.Type);
    }
}

void pause_for_debugger(const char* message) {
    printf("\n[!] DEBUGGER CHECKPOINT\n");
    printf("    %s\n", message);
    printf("    Process ID: %lu\n", GetCurrentProcessId());
    printf("\n[#] Press <ENTER> to continue...\n");
    (void)getchar();
}