/*
Credits to : https://github.com/wavestone-cdt/EDRSandblast
*/
#include "common.h"

#include <tchar.h>
#include <stdio.h>
#include <shlwapi.h>
#include <psapi.h>

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#include "sandblast.h"

// Function to load ntoskrnl.exe offsets from the Internet by fetching symbol information
BOOL LoadNtoskrnlOffsetsFromInternet(BOOL delete_pdb) {

    // Load the symbol table from the `ntoskrnl.exe`
    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(GetNtoskrnlPath());
    if (sym_ctx == NULL) {
        return FALSE;
    }
    infoW_t(L"LoadSymbolsFromImageFile - Symbols from \"ntoskrnl.exe\" loaded");

    // Get the offset of the ETWI Reg handle
    g_ntoskrnlOffsets.st.etwThreatIntProvRegHandle = GetSymbolOffset(sym_ctx, "EtwThreatIntProvRegHandle");

    // Get the offset of the GuidEntry
    g_ntoskrnlOffsets.st.etwRegEntry_GuidEntry = GetFieldOffset(sym_ctx, "_ETW_REG_ENTRY", L"GuidEntry");

    // Get the offset of the ProviderEnableInfo
    g_ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo = GetFieldOffset(sym_ctx, "_ETW_GUID_ENTRY", L"ProviderEnableInfo");

    // Unload the symbols after retrieving the required offsets.
    // If `delete_pdb` is TRUE, it ensures that temporary symbol files are removed.
    UnloadSymbols(sym_ctx, delete_pdb);

    // Ensure that at least one of the offsets was successfully retrieved.
    // If all three offsets are 0, it indicates failure.
    if (!g_ntoskrnlOffsets.st.etwThreatIntProvRegHandle && !g_ntoskrnlOffsets.st.etwRegEntry_GuidEntry &&!g_ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo) {
        return FALSE;
    }
    // Return TRUE if at least one offset was successfully retrieved.
    return TRUE;

}

// Function to print Ntoskrnl offsets with attribute names
void PrintOffsets() {
    info_t("Ntoskrnl offsets:");
    info_t("\t - etwThreatIntProvRegHandle:\t\t 0x%llx", g_ntoskrnlOffsets.st.etwThreatIntProvRegHandle);
    info_t("\t - etwRegEntry_GuidEntry:\t\t 0x%llx", g_ntoskrnlOffsets.st.etwRegEntry_GuidEntry);
    info_t("\t - etwGuidEntry_ProviderEnableInfo:\t 0x%llx", g_ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo);
}

// Finds the base address of a kernel module by name
DWORD64 FindKernelModuleAddressByName(_In_ LPTSTR name) {
    LPVOID drivers[1024] = { 0 };
    DWORD cbNeeded;
    DWORD cDrivers = 0;
    TCHAR szDriver[1024] = { 0 };

    // Get a list of loaded kernel modules
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (DWORD i = 0; i < cDrivers; i++) {

            // Get module name and compare it with the target name
            if (drivers[i] && GetDeviceDriverBaseName(drivers[i], szDriver, _countof(szDriver))) {
                if (_tcsicmp(szDriver, name) == 0) {
                    return (DWORD64)drivers[i];
                }
            }
        }
    }
    error("Could not resolve %s kernel module's address", name);

    return EXIT_FAILURE;
}

// Retrieves the base address of CI.dll
DWORD64 FindCIBaseAddress() {
    DWORD64 CiBaseAddress = FindKernelModuleAddressByName((LPTSTR)TEXT("CI.dll"));
    return CiBaseAddress;
}

TCHAR g_ntoskrnlPath[MAX_PATH] = { 0 };
LPTSTR GetNtoskrnlPath() {
    if (_tcslen(g_ntoskrnlPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        GetSystemDirectory(g_ntoskrnlPath, _countof(g_ntoskrnlPath));

        // Compute ntoskrnl.exe path.
        PathAppend(g_ntoskrnlPath, TEXT("\\ntoskrnl.exe"));
    }
    return g_ntoskrnlPath;
}

//void GetFileVersion(TCHAR* buffer, SIZE_T bufferLen, TCHAR* filename) {
//    DWORD verHandle = 0;
//    UINT size = 0;
//    LPVOID lpBuffer = NULL;
//
//    DWORD verSize = GetFileVersionInfoSize(filename, &verHandle);
//
//    if (verSize != 0) {
//        LPTSTR verData = (LPTSTR)calloc(verSize, 1);
//
//        if (!verData) {
//            printf("[!] Couldn't allocate memory to retrieve version data");
//            return;
//        }
//
//        if (GetFileVersionInfo(filename, 0, verSize, verData)) {
//            if (VerQueryValue(verData, TEXT("\\"), &lpBuffer, &size)) {
//                if (size) {
//                    VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
//                    if (verInfo->dwSignature == 0xfeef04bd) {
//                        DWORD majorVersion = (verInfo->dwFileVersionLS >> 16) & 0xffff;
//                        DWORD minorVersion = (verInfo->dwFileVersionLS >> 0) & 0xffff;
//                        _stprintf_s(buffer, bufferLen, TEXT("%ld-%ld"), majorVersion, minorVersion);
//                        // _tprintf_or_not(TEXT("File Version: %d.%d\n"), majorVersion, minorVersion);
//                    }
//                }
//            }
//        }
//        free(verData);
//    }
//}
//
//TCHAR g_ntoskrnlVersion[256] = { 0 };
//LPTSTR GetNtoskrnlVersion() {
//    if (_tcslen(g_ntoskrnlVersion) == 0) {
//
//        LPTSTR ntoskrnlPath = GetNtoskrnlPath();
//        TCHAR versionBuffer[256] = { 0 };
//        GetFileVersion(versionBuffer, _countof(versionBuffer), ntoskrnlPath);
//        _stprintf_s(g_ntoskrnlVersion, 256, TEXT("ntoskrnl_%s.exe"), versionBuffer);
//    }
//    return g_ntoskrnlVersion;
//}