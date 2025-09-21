#include "PPLHelp.h"

DWORD PPLProcessCreator::GetPPLProtectionLevel(DWORD processId)
{
    DWORD protectionLevel = 0;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);

    if (hProcess)
    {
        PROCESS_PROTECTION_LEVEL_INFORMATION protectionInfo;
        DWORD returnLength = 0;

        if (GetProcessInformation(hProcess, ProcessProtectionLevelInfo,
            &protectionInfo, sizeof(protectionInfo)))
        {
            protectionLevel = protectionInfo.ProtectionLevel;
        }

        CloseHandle(hProcess);
    }

    return protectionLevel;
}
std::wstring PPLProcessCreator::GetPPLProtectionLevelName(DWORD protectionLevel)
{
    std::wcout << L"Protection Level: " << protectionLevel << std::endl;
    switch (protectionLevel)
    {
    case PROTECTION_LEVEL_WINTCB_LIGHT:
        return L"PROTECTION_LEVEL_WINTCB_LIGHT";
    case PROTECTION_LEVEL_WINDOWS:
        return L"PROTECTION_LEVEL_WINDOWS";
    case PROTECTION_LEVEL_WINDOWS_LIGHT:
        return L"PROTECTION_LEVEL_WINDOWS_LIGHT";
    case PROTECTION_LEVEL_ANTIMALWARE_LIGHT:
        return L"PROTECTION_LEVEL_ANTIMALWARE_LIGHT";
    case PROTECTION_LEVEL_LSA_LIGHT:
        return L"PROTECTION_LEVEL_LSA_LIGHT";
    default:
        return L"Unknown protection level";
    }
}
DWORD PPLProcessCreator::CreatePPLProcess(DWORD protectionLevel, std::wstring& commandLine)
{
    SIZE_T size = 0;
    STARTUPINFOEXW siex = { 0 };
    siex.StartupInfo.cb = sizeof(siex);
    PROCESS_INFORMATION pi = { 0 };
    LPPROC_THREAD_ATTRIBUTE_LIST ptal = nullptr;

    // Initialize attribute list size
    if (!InitializeProcThreadAttributeList(nullptr, 1, 0, &size) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        std::wcerr << L"InitializeProcThreadAttributeList failed: " << GetLastError() << std::endl;
        return 0;
    }

    // Allocate attribute list
    ptal = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, size));
    if (!ptal)
    {
        std::wcerr << L"HeapAlloc failed: " << GetLastError() << std::endl;
        return 0;
    }

    // Initialize attribute list
    if (!InitializeProcThreadAttributeList(ptal, 1, 0, &size))
    {
        std::wcerr << L"InitializeProcThreadAttributeList failed: " << GetLastError() << std::endl;
        HeapFree(GetProcessHeap(), 0, ptal);
        return 0;
    }

    // Set protection level
    //DWORD protectionLevel = PROTECTION_LEVEL_ANTIMALWARE_LIGHT;
    if (!UpdateProcThreadAttribute(ptal, 0, PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, &protectionLevel, sizeof(protectionLevel), nullptr, nullptr))
    {
        std::wcerr << L"UpdateProcThreadAttribute failed: " << GetLastError() << std::endl;
        DeleteProcThreadAttributeList(ptal);
        HeapFree(GetProcessHeap(), 0, ptal);
        return 0;
    }
    siex.lpAttributeList = ptal;

    // Create process with PPL protection
    if (!CreateProcessW(
        nullptr,    // Application name
        (LPWSTR)commandLine.c_str(),      // Command line
        nullptr,                   // Process security attributes
        nullptr,                   // Thread security attributes
        TRUE,                     // Inherit handles
        EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
        nullptr,                   // Environment
        nullptr,                   // Current directory
        &siex.StartupInfo,         // Startup info
        &pi))                       // Process information
    {
        std::wcerr << L"CreateProcessW failed: " << GetLastError() << std::endl;
        DeleteProcThreadAttributeList(ptal);
        HeapFree(GetProcessHeap(), 0, ptal);
        return 0;
    }

    // Clean up attribute list
    DeleteProcThreadAttributeList(ptal);
    HeapFree(GetProcessHeap(), 0, ptal);

    m_hProcess = pi.hProcess;
    m_hThread = pi.hThread;

    std::wcout << L"Successfully created PPL process with PID: " << pi.dwProcessId << std::endl;
    std::wcerr << L"Protection level: " << GetPPLProtectionLevelName(GetPPLProtectionLevel(pi.dwProcessId)) << std::endl;

    //DWORD result = WaitForSingleObject(m_hProcess, INFINITE);
    //if (result == WAIT_OBJECT_0)
    //{
    //    DWORD exitCode;
    //    GetExitCodeProcess(m_hProcess, &exitCode);
    //    std::wcout << L"Process WerfaultSecure.exe exited with code: " << exitCode << std::endl;
    //}

    return pi.dwProcessId;
}

HANDLE PPLProcessCreator::GetProcessHandle()  { return m_hProcess; }
HANDLE PPLProcessCreator::GetThreadHandle()  { return m_hThread; }