#include "ProcessMisc.h"

// Convert HANDLE to decimal string
std::wstring HandleToDecimal(HANDLE h)
{
    std::wstringstream ss;
    ss << reinterpret_cast<UINT_PTR>(h);
    return ss.str();
}

bool EnableDebugPrivilege()
{
    HANDLE hToken = nullptr;
    TOKEN_PRIVILEGES tp = {};
    LUID luid;

    // Open the current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::wcerr << L"OpenProcessToken failed: " << GetLastError() << L"\n";
        return false;
    }

    // Lookup the LUID for SeDebugPrivilege
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
    {
        std::wcerr << L"LookupPrivilegeValue failed: " << GetLastError() << L"\n";
        CloseHandle(hToken);
        return false;
    }

    // Enable the privilege
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
    {
        std::wcerr << L"AdjustTokenPrivileges failed: " << GetLastError() << L"\n";
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);

    // Check for success
    if (GetLastError() == ERROR_SUCCESS)
    {
        std::wcout << L"SeDebugPrivilege enabled successfully.\n";
        return true;
    }
    else
    {
        std::wcerr << L"AdjustTokenPrivileges reported error: " << GetLastError() << L"\n";
        return false;
    }
}

DWORD GetMainThreadId(DWORD pid)
{
    ULONG bufferSize = 0x10000;
    PVOID buffer = nullptr;
    NTSTATUS status;
    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    do {
        buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return 0;

        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, nullptr);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            bufferSize *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    DWORD mainThreadId = 0;
    LARGE_INTEGER earliestCreateTime = { 0x7FFFFFFFFFFFFFFF };
    auto spi = (MY_SYSTEM_PROCESS_INFORMATION*)buffer;

    while (true) {
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid)
        {
            if (spi->NumberOfThreads > 0)
            {
                mainThreadId = (DWORD)(ULONG_PTR)spi->Threads[0].ClientId.UniqueThread;
            }
            break;
        }

        if (spi->NextEntryOffset == 0) break;
        spi = (MY_SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return mainThreadId;
}

BOOL IsProcessSuspendedByPID(DWORD pid)
{
    ULONG bufferSize = 0x10000;
    PVOID buffer = nullptr;
    NTSTATUS status;
    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    do {
        buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return FALSE;

        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, nullptr);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            bufferSize *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    DWORD mainThreadId = 0;
    LARGE_INTEGER earliestCreateTime = { 0x7FFFFFFFFFFFFFFF };
    auto spi = (MY_SYSTEM_PROCESS_INFORMATION*)buffer;

    while (true)
    {
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid)
        {
            // If no threads, consider not suspended
            if (spi->NumberOfThreads == 0) return FALSE;

            // Thread info array immediately follows the SYSTEM_PROCESS_INFORMATION struct
            PSYSTEM_THREAD_INFORMATION threadInfo = (PSYSTEM_THREAD_INFORMATION)((PBYTE)spi + sizeof(SYSTEM_PROCESS_INFORMATION));
            for (ULONG i = 0; i < spi->NumberOfThreads; ++i)
            {
                // Check thread state and wait reason
                if (threadInfo[i].ThreadState != StateWait || threadInfo[i].WaitReason != Suspended)
                {
                    return FALSE;
                }
            }
            return TRUE;
            break;
        }

        if (spi->NextEntryOffset == 0) break;
        spi = (MY_SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return mainThreadId;
}

BOOL SuspendProcessByPID(DWORD pid)
{
    // Load ntdll.dll and get the address of NtSuspendProcess
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
    if (!NtSuspendProcess) return false;

    // Open the target process with PROCESS_SUSPEND_RESUME access
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess)
    {
        std::wcerr << L"OpenProcess: PROCESS_SUSPEND_RESUME failed: " << GetLastError() << std::endl;
        return false;
    }

    // Call NtSuspendProcess
    NTSTATUS status = NtSuspendProcess(hProcess);
    CloseHandle(hProcess);
    if (status != 0)
    {
        std::wcerr << "NtSuspendProcess failed. Error code: " << GetLastError() << std::endl;
        return false;
    }
    std::wcout << "Process suspended successfully.\n";
    return true;
}

BOOL TerminateProcessByPID(DWORD pid)
{
    // Open the process with termination rights
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << "\n";
        return false;
    }
    BOOL result = TerminateProcess(hProcess, 1); // Exit code = 1
    if (!result)
    {
        std::cerr << "TerminateProcess failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    CloseHandle(hProcess);
    std::cout << "Process terminated successfully.\n";
    return true;
}
