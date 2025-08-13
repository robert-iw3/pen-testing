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

// Function to load fltMgr.sys offsets from the Internet by fetching symbol information
BOOL LoadfltMgrOffsetsFromInternet(BOOL delete_pdb) {

    // Load the symbol table from the `fltMgr.sys`
    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(GetfltMgrPath());
    if (sym_ctx == NULL) {
        return FALSE;
    }
    infoW_t(L"LoadSymbolsFromImageFile - Symbols from \"fltMgr.sys\" loaded");

    // Get all the required offsets
    g_fltMgrOffsets.st.FltGlobals = GetSymbolOffset(sym_ctx, "FltGlobals");
    g_fltMgrOffsets.st._DRIVER_OBJECT_DriverInit = GetFieldOffset(sym_ctx, "_DRIVER_OBJECT", L"DriverInit");
    g_fltMgrOffsets.st._FLTP_FRAME_Links = GetFieldOffset(sym_ctx, "_FLTP_FRAME", L"Links");
    g_fltMgrOffsets.st._FLTP_FRAME_RegisteredFilters = GetFieldOffset(sym_ctx, "_FLTP_FRAME", L"RegisteredFilters");
    g_fltMgrOffsets.st._FLT_FILTER_DriverObject = GetFieldOffset(sym_ctx, "_FLT_FILTER", L"DriverObject");
    g_fltMgrOffsets.st._FLT_FILTER_InstanceList = GetFieldOffset(sym_ctx, "_FLT_FILTER", L"InstanceList");
    g_fltMgrOffsets.st._FLT_INSTANCE_CallbackNodes = GetFieldOffset(sym_ctx, "_FLT_INSTANCE", L"CallbackNodes");
    g_fltMgrOffsets.st._FLT_INSTANCE_FilterLink = GetFieldOffset(sym_ctx, "_FLT_INSTANCE", L"FilterLink");
    g_fltMgrOffsets.st._FLT_OBJECT_PrimaryLink = GetFieldOffset(sym_ctx, "_FLT_OBJECT", L"PrimaryLink");
    g_fltMgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList = GetFieldOffset(sym_ctx, "_FLT_RESOURCE_LIST_HEAD", L"rList");
    g_fltMgrOffsets.st._GLOBALS_FrameList = GetFieldOffset(sym_ctx, "_GLOBALS", L"FrameList");

    // Unload the symbols after retrieving the required offsets.
    // If `delete_pdb` is TRUE, it ensures that temporary symbol files are removed.
    UnloadSymbols(sym_ctx, delete_pdb);

    // Ensure that at least one of the offsets was successfully retrieved.
    // If all offsets are 0, it indicates failure.
    if (
        !g_fltMgrOffsets.st.FltGlobals ||
        !g_fltMgrOffsets.st._DRIVER_OBJECT_DriverInit ||
        !g_fltMgrOffsets.st._FLTP_FRAME_Links ||
        !g_fltMgrOffsets.st._FLTP_FRAME_RegisteredFilters ||
        !g_fltMgrOffsets.st._FLT_FILTER_DriverObject ||
        !g_fltMgrOffsets.st._FLT_FILTER_InstanceList ||
        !g_fltMgrOffsets.st._FLT_INSTANCE_CallbackNodes ||
        !g_fltMgrOffsets.st._FLT_INSTANCE_FilterLink ||
        !g_fltMgrOffsets.st._FLT_OBJECT_PrimaryLink ||
        !g_fltMgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList ||
        !g_fltMgrOffsets.st._GLOBALS_FrameList
        ) {
        return FALSE;
    }

    // Return TRUE if at least one offset was successfully retrieved.
    return TRUE;

}

// Function to print Ntoskrnl offsets with attribute names
void PrintfltMgrOffsets() {
    info_t("fltMgr offsets:");
    info_t(" - Symbol offset FltGlobals:                       0x%llx", g_fltMgrOffsets.st.FltGlobals);
    info_t(" - Field offset _DRIVER_OBJECT.DriverInit:         0x%llx", g_fltMgrOffsets.st._DRIVER_OBJECT_DriverInit);
    info_t(" - Field offset _FLTP_FRAME.Links:                 0x%llx", g_fltMgrOffsets.st._FLTP_FRAME_Links);
    info_t(" - Field offset _FLTP_FRAME.RegisteredFilters:     0x%llx", g_fltMgrOffsets.st._FLTP_FRAME_RegisteredFilters);
    info_t(" - Field offset _FLT_FILTER.DriverObject:          0x%llx", g_fltMgrOffsets.st._FLT_FILTER_DriverObject);
    info_t(" - Field offset _FLT_FILTER.InstanceList:          0x%llx", g_fltMgrOffsets.st._FLT_FILTER_InstanceList);
    info_t(" - Field offset _FLT_INSTANCE.CallbackNodes:       0x%llx", g_fltMgrOffsets.st._FLT_INSTANCE_CallbackNodes);
    info_t(" - Field offset _FLT_INSTANCE.FilterLink:          0x%llx", g_fltMgrOffsets.st._FLT_INSTANCE_FilterLink);
    info_t(" - Field offset _FLT_OBJECT.PrimaryLink:           0x%llx", g_fltMgrOffsets.st._FLT_OBJECT_PrimaryLink);
    info_t(" - Field offset _FLT_RESOURCE_LIST_HEAD.rList:     0x%llx", g_fltMgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList);
    info_t(" - Field offset _GLOBALS.FrameList:                0x%llx", g_fltMgrOffsets.st._GLOBALS_FrameList);
};

TCHAR g_fltMgrPath[MAX_PATH] = { 0 };
LPTSTR GetfltMgrPath() {
    if (_tcslen(g_fltMgrPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        GetSystemDirectory(g_fltMgrPath, _countof(g_fltMgrPath));

        // Compute ntoskrnl.exe path.
        PathAppend(g_fltMgrPath, TEXT("\\drivers\\fltMgr.sys"));
    }
    return g_fltMgrPath;
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

// Retrieves the base address of fltMgr.sys
DWORD64 GetfltMgrBaseAddress() {
    DWORD64 fltMgrBaseAddress = FindKernelModuleAddressByName((LPTSTR)TEXT("fltmgr.sys"));
    return fltMgrBaseAddress;
}