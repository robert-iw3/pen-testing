#include <Windows.h>
#include <intrin.h>

EXTERN_C NTSTATUS DirectNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    constexpr DWORD syscallId = 0x18; // Win10 2004

    __asm {
        mov r10, rcx
        mov eax, syscallId
        syscall
        ret
    }
}

template<DWORD Id, typename... Args>
NTSTATUS SyscallInvoker(Args... args) {
    return reinterpret_cast<NTSTATUS(*)(Args...)>(GetSyscallStub(Id))(args...);
}

PVOID GetSyscallStub(DWORD syscallId) {
    /**
      Dynamically resolve syscall address
      -> [Implementation varies per Windows version]
    **/
    return nullptr; // placeholder
}

// Usage:
// PVOID addr = nullptr;
// SIZE_T size = 0x1000;
// DirectNtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
