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

    // Get the offset for each kernel callbacks
    g_ntoskrnlOffsets.st.pspCreateProcessNotifyRoutine  = GetSymbolOffset(sym_ctx, "PspCreateProcessNotifyRoutine");
    g_ntoskrnlOffsets.st.pspCreateThreadNotifyRoutine   = GetSymbolOffset(sym_ctx, "PspCreateThreadNotifyRoutine");
    g_ntoskrnlOffsets.st.pspLoadImageNotifyRoutine      = GetSymbolOffset(sym_ctx, "PspLoadImageNotifyRoutine");
    g_ntoskrnlOffsets.st.CallbackListHead               = GetSymbolOffset(sym_ctx, "CallbackListHead");
    g_ntoskrnlOffsets.st.psProcessType                  = GetSymbolOffset(sym_ctx, "PsProcessType");
    g_ntoskrnlOffsets.st.psThreadType                   = GetSymbolOffset(sym_ctx, "PsThreadType");
    g_ntoskrnlOffsets.st.object_type_callbacklist       = GetFieldOffset(sym_ctx, "_OBJECT_TYPE", L"CallbackList");

    // Unload the symbols after retrieving the required offsets.
    // If `delete_pdb` is TRUE, it ensures that temporary symbol files are removed.
    UnloadSymbols(sym_ctx, delete_pdb);

    // Ensure that at least one of the offsets was successfully retrieved.
    // If all offsets are 0, it indicates failure.
    if (!g_ntoskrnlOffsets.st.pspCreateProcessNotifyRoutine 
        && !g_ntoskrnlOffsets.st.pspCreateThreadNotifyRoutine 
        && !g_ntoskrnlOffsets.st.pspLoadImageNotifyRoutine
        && !g_ntoskrnlOffsets.st.CallbackListHead
        && !g_ntoskrnlOffsets.st.psProcessType
        && !g_ntoskrnlOffsets.st.psThreadType
        && !g_ntoskrnlOffsets.st.object_type_callbacklist) {
        return FALSE;
    }
    
    // Return TRUE if at least one offset was successfully retrieved.
    return TRUE;

}

// Function to print Ntoskrnl offsets with attribute names
void PrintNtoskrnlOffsets() {
    info_t("Ntoskrnl Kernel Callback offsets:");
    info_t(" - Symb offset pspCreateProcessNotifyRoutine:    0x%llx", g_ntoskrnlOffsets.st.pspCreateProcessNotifyRoutine);
    info_t(" - Symb offset pspCreateThreadNotifyRoutine:     0x%llx", g_ntoskrnlOffsets.st.pspCreateThreadNotifyRoutine);
    info_t(" - Symb offset pspLoadImageNotifyRoutine:        0x%llx", g_ntoskrnlOffsets.st.pspLoadImageNotifyRoutine);
    info_t(" - Symb offset CallbackListHead:                 0x%llx", g_ntoskrnlOffsets.st.CallbackListHead);
    info_t(" - Symb offset PsProcessType:                    0x%llx", g_ntoskrnlOffsets.st.psProcessType);
    info_t(" - Symb offset PsThreadType:                     0x%llx", g_ntoskrnlOffsets.st.psThreadType);
    info_t(" - Field offset _OBJECT_TYPE.Callbacklist:       0x%llx", g_ntoskrnlOffsets.st.object_type_callbacklist);
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