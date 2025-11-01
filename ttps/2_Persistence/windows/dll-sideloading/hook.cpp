#include "hook.h"

typedef HWND(WINAPI* PFN_CREATE_WINDOW_EX_W)(
    DWORD     dwExStyle,
    LPCWSTR   lpClassName,
    LPCWSTR   lpWindowName,
    DWORD     dwStyle,
    int       X,
    int       Y,
    int       nWidth,
    int       nHeight,
    HWND      hWndParent,
    HMENU     hMenu,
    HINSTANCE hInstance,
    LPVOID    lpParam
    );

PFN_CREATE_WINDOW_EX_W g_pfnOriginalCreateWindowExW = NULL;
DWORD g_dwOriginalProtect = 0;

HWND WINAPI HookedCreateWindowExW(
    DWORD     dwExStyle,
    LPCWSTR   lpClassName,
    LPCWSTR   lpWindowName,
    DWORD     dwStyle,
    int       X,
    int       Y,
    int       nWidth,
    int       nHeight,
    HWND      hWndParent,
    HMENU     hMenu,
    HINSTANCE hInstance,
    LPVOID    lpParam
) {
    if (dwStyle & WS_VISIBLE) {
        dwStyle &= ~WS_VISIBLE;
    }

    return g_pfnOriginalCreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

LONG NTAPI VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        if (pExceptionInfo->ExceptionRecord->ExceptionAddress == g_pfnOriginalCreateWindowExW)
        {
            pExceptionInfo->ContextRecord->Rip = (DWORD64)HookedCreateWindowExW;
        }

        pExceptionInfo->ContextRecord->EFlags |= 0x100;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        DWORD oldProtect;
        VirtualProtect(g_pfnOriginalCreateWindowExW, 1, g_dwOriginalProtect | PAGE_GUARD, &oldProtect);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void InstallHook() {
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) return;

    g_pfnOriginalCreateWindowExW = (PFN_CREATE_WINDOW_EX_W)GetProcAddress(hUser32, "CreateWindowExW");
    if (!g_pfnOriginalCreateWindowExW) return;

    AddVectoredExceptionHandler(1, VectoredHandler);

    DWORD oldProtect;
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(g_pfnOriginalCreateWindowExW, &mbi, sizeof(mbi));
    g_dwOriginalProtect = mbi.Protect;

    VirtualProtect(g_pfnOriginalCreateWindowExW, 1, g_dwOriginalProtect | PAGE_GUARD, &oldProtect);
}