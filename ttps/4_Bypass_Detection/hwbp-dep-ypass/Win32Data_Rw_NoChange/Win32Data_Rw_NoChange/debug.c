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

void start_debug_session_failure(const char* message) {
    ensure_unbuffered_output();
    print_separator('=');
    printf("  FAILURE DEMONSTRATION: DEP/NX PROTECTION IN ACTION\n");
    printf("  Attempting to Execute from Non-Executable Memory\n");
    print_separator('=');
    printf("\n[!] WARNING: This program will intentionally crash!\n");
    printf("[!] This demonstrates WHY memory protection bypass is needed.\n");
    printf("\n[#] %s\n", message);
    (void)getchar();
}

void show_nonexecutable_memory_state(unsigned char* shellcode, size_t size) {
    print_separator('-');
    printf("STEP 1: ANALYZING NON-EXECUTABLE MEMORY\n");
    print_separator('-');

    printf("\n[+] Shellcode location:\n");
    printf("    Base address: 0x%p\n", (void*)shellcode);
    printf("    Size: %zu bytes (0x%zX)\n", size, size);
    printf("    Section: .data (non-executable by default)\n");

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
    printf("    ┌────────────────────────────────────────────────────┐\n");
    printf("    │ Current protection: PAGE_READWRITE (0x04)         │\n");
    printf("    │ NX bit status: ENABLED ✓                          │\n");
    printf("    │                                                    │\n");
    printf("    │ Permissions:                                       │\n");
    printf("    │   Read:    YES ✓                                  │\n");
    printf("    │   Write:   YES ✓                                  │\n");
    printf("    │   Execute: NO ✗ (BLOCKED BY DEP/NX)              │\n");
    printf("    └────────────────────────────────────────────────────┘\n");

    printf("\n[#] Shellcode bytes (readable as data):\n");
    dump_shellcode_bytes_failure(shellcode, size);

    printf("\n[#] Press <ENTER> to continue...\n");
    (void)getchar();
}

void explain_expected_crash(unsigned char* shellcode) {
    print_separator('-');
    printf("STEP 2: UNDERSTANDING THE EXPECTED CRASH\n");
    print_separator('-');

    printf("\n[*] What will happen when we try to execute:\n\n");

    printf("    1. Code attempts: ((void(*)())shellcode)()\n");
    printf("       └─> This casts shellcode address to function pointer\n\n");

    printf("    2. CALL instruction is executed\n");
    printf("       └─> Pushes return address to stack\n");
    printf("       └─> Sets RIP = 0x%p\n\n", (void*)shellcode);

    printf("    3. CPU attempts to FETCH instruction from RIP\n");
    printf("       └─> Tries to read instruction from 0x%p\n\n", (void*)shellcode);

    printf("    4. Memory Management Unit (MMU) checks page protection\n");
    printf("       └─> Checks NX (No-eXecute) bit in page table entry\n");
    printf("       └─> Page protection: PAGE_READWRITE (no execute permission)\n");
    printf("       └─> NX bit: ENABLED ✓\n\n");

    printf("    5. MMU BLOCKS the instruction fetch\n");
    printf("       └─> Instruction fetch from non-executable memory DENIED\n\n");

    printf("    6. CPU generates exception\n");
    printf("       └─> Exception Code: 0xC0000005\n");
    printf("       └─> Exception Name: EXCEPTION_ACCESS_VIOLATION\n");
    printf("       └─> Reason: Execute permission denied\n\n");

    printf("    7. Windows exception handling\n");
    printf("       └─> Searches for exception handlers\n");
    printf("       └─> Our __except block catches it\n");
    printf("       └─> Or: Program crashes with access violation\n\n");

    printf("\n[!] KEY POINT:\n");
    printf("    The CPU never actually executes the instruction!\n");
    printf("    The exception occurs DURING the instruction fetch,\n");
    printf("    BEFORE the instruction can be decoded or executed.\n");

    printf("\n[!] This is DEP (Data Execution Prevention) / NX in action.\n");
    printf("    It prevents code execution from data pages.\n");

    printf("\n[#] Press <ENTER> to continue...\n");
    (void)getchar();
}

void prepare_for_crash() {
    print_separator('-');
    printf("STEP 3: READY TO TRIGGER ACCESS VIOLATION\n");
    print_separator('-');

    printf("\n[*] Current state:\n");
    printf("    ✓ Shellcode in non-executable memory\n");
    printf("    ✓ No VirtualProtect called\n");
    printf("    ✓ Memory protection unchanged (PAGE_READWRITE)\n");
    printf("    ✓ Exception handler installed (__try/__except)\n");

    printf("\n[!] DEBUGGER SETUP:\n");
    printf("    If you want to see this in x64dbg:\n");
    printf("    1. Attach debugger now\n");
    printf("    2. Process ID: %lu\n", GetCurrentProcessId());
    printf("    3. Set exception breakpoint on access violations\n");
    printf("    4. You will see the CPU halt at the FETCH attempt\n");
    printf("    5. Registers will show RIP pointing to shellcode\n");
    printf("    6. Exception 0xC0000005 will be raised\n");

    printf("\n[!] When you press ENTER, the program will:\n");
    printf("    1. Attempt to execute shellcode\n");
    printf("    2. Trigger EXCEPTION_ACCESS_VIOLATION\n");
    printf("    3. Catch exception in __except handler\n");
    printf("    4. Display crash analysis\n");
    printf("    5. Continue execution (not crash the process)\n");

    printf("\n[#] Press <ENTER> to trigger the access violation...\n");
    (void)getchar();
}

void show_crash_analysis(DWORD exceptionCode, unsigned char* shellcode) {
    print_separator('-');
    printf("STEP 4: CRASH ANALYSIS\n");
    print_separator('-');

    printf("\n[!] EXCEPTION CAUGHT BY __except HANDLER\n");
    printf("\n[+] Exception details:\n");
    printf("    Exception Code:   0x%08lX\n", exceptionCode);

    if (exceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        printf("    Exception Name:   EXCEPTION_ACCESS_VIOLATION\n");
        printf("    Common Name:      Access Violation / Segmentation Fault\n");
        printf("    Description:      Attempted to access memory illegally\n");
        printf("    Specific Reason:  Attempted to EXECUTE non-executable memory\n");
        printf("    Failed Address:   0x%p\n", (void*)shellcode);

        printf("\n[+] What happened:\n");
        printf("    ✓ Program attempted to execute code at 0x%p\n", (void*)shellcode);
        printf("    ✓ CPU tried to fetch instruction from this address\n");
        printf("    ✓ MMU checked page table entry\n");
        printf("    ✓ NX bit was SET (execute permission denied)\n");
        printf("    ✓ MMU blocked the instruction fetch\n");
        printf("    ✓ Exception 0xC0000005 was raised\n");
        printf("    ✓ Our __except handler caught it\n");
        printf("    ✓ Program continues (instead of crashing)\n");

        printf("\n[+] Memory protection that caused the crash:\n");
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (VirtualQuery(shellcode, &mbi, sizeof(mbi))) {
            printf("    Protection: 0x%08lX (%s)\n",
                mbi.Protect, protection_to_string(mbi.Protect));
            printf("    Execute permission: DENIED ✗\n");
        }

        printf("\n[!] WHY THIS MATTERS:\n");
        printf("    This is the PROBLEM that bypass techniques must solve:\n");
        printf("    - Traditional method: Call VirtualProtect to make memory executable\n");
        printf("    - Hardware breakpoint method: Never actually execute from this memory\n");
        printf("    - Other methods: ROP, JOP, memory mapping tricks, etc.\n");

    }
    else {
        printf("    Exception Name:   UNKNOWN (0x%08lX)\n", exceptionCode);
        printf("    This is not the expected exception!\n");
    }

    printf("\n[#] Press <ENTER> to continue...\n");
    (void)getchar();
}

void show_failure_summary() {
    print_separator('=');
    printf("FAILURE DEMONSTRATION COMPLETED\n");
    print_separator('=');

    printf("\n[+] Summary of what we learned:\n\n");

    printf("    1. DEFAULT STATE:\n");
    printf("       - .data section has PAGE_READWRITE protection\n");
    printf("       - NX (No-eXecute) bit is ENABLED\n");
    printf("       - Memory can be read and written, but NOT executed\n\n");

    printf("    2. ATTEMPTED EXECUTION:\n");
    printf("       - Tried to execute code from .data section\n");
    printf("       - CPU attempted to fetch instruction\n");
    printf("       - MMU checked NX bit\n");
    printf("       - Access was DENIED\n\n");

    printf("    3. EXCEPTION RAISED:\n");
    printf("       - EXCEPTION_ACCESS_VIOLATION (0xC0000005)\n");
    printf("       - Caught by __except handler\n");
    printf("       - Without handler, program would crash\n\n");

    printf("    4. THE SECURITY MECHANISM:\n");
    printf("       - This is DEP/NX protection working correctly\n");
    printf("       - Prevents arbitrary code execution from data pages\n");
    printf("       - Critical defense against many exploits\n\n");

    printf("    5. WHY BYPASS TECHNIQUES EXIST:\n");
    printf("       - Malware needs to execute shellcode\n");
    printf("       - Shellcode is often in RW memory (heap, stack, .data)\n");
    printf("       - Cannot execute directly due to DEP/NX\n");
    printf("       - Must use bypass technique:\n");
    printf("         • VirtualProtect (detected by EDR)\n");
    printf("         • Hardware breakpoint emulation (stealthy)\n");
    printf("         • ROP chains (complex)\n");
    printf("         • Memory mapping tricks\n\n");

    printf("\n[*] Next Step:\n");
    printf("    See how VirtualProtect solves this by changing protection.\n");
    printf("    Then see how hardware breakpoints bypass without VirtualProtect.\n");

    print_separator('=');
    printf("\n[#] Press <ENTER> to exit...\n");
    (void)getchar();
}

void dump_shellcode_bytes_failure(unsigned char* shellcode, size_t size) {
    printf("    Offset  Bytes                                            ASCII       Instruction\n");
    printf("    ------  -----------------------------------------------  ----------  ------------\n");

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

        // Pad ASCII column
        for (size_t j = size - i; j < 16 && size - i < 16; j++) {
            printf(" ");
        }

        printf("  ");

        // Instruction comments
        if (i == 0) {
            printf("NOP (0x90)");
        }
        else if (i < 5) {
            printf("NOP (0x90)");
        }
        else if (shellcode[i] == 0xC3) {
            printf("RET (0xC3)");
        }

        printf("\n");
    }

    printf("\n    [*] These bytes are READABLE as data\n");
    printf("    [*] But CANNOT be executed (NX bit set)\n");
}

void dump_memory_region_failure(void* address) {
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