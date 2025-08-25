#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

#pragma comment(lib, "advapi32.lib")

class PPLProcessCreator
{
private:
    HANDLE m_hProcess;
    HANDLE m_hThread;

public:
    PPLProcessCreator() : m_hProcess(nullptr), m_hThread(nullptr) {}
    ~PPLProcessCreator()
    {
        if (m_hProcess) CloseHandle(m_hProcess);
        if (m_hThread) CloseHandle(m_hThread);
    }

    DWORD GetPPLProtectionLevel(DWORD processId)
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
    std::wstring GetPPLProtectionLevelName(DWORD protectionLevel)
    {
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
    bool CreatePPLProcess(DWORD protectionLevel, const std::wstring& executablePath, const std::wstring& commandLine = L"")
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
            return false;
        }

        // Allocate attribute list
        ptal = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, size));
        if (!ptal)
        {
            std::wcerr << L"HeapAlloc failed: " << GetLastError() << std::endl;
            return false;
        }

        // Initialize attribute list
        if (!InitializeProcThreadAttributeList(ptal, 1, 0, &size))
        {
            std::wcerr << L"InitializeProcThreadAttributeList failed: " << GetLastError() << std::endl;
            HeapFree(GetProcessHeap(), 0, ptal);
            return false;
        }

        // Set protection level
        //DWORD protectionLevel = PROTECTION_LEVEL_ANTIMALWARE_LIGHT;
        if (!UpdateProcThreadAttribute(ptal, 0, PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, &protectionLevel, sizeof(protectionLevel), nullptr, nullptr))
        {
            std::wcerr << L"UpdateProcThreadAttribute failed: " << GetLastError() << std::endl;
            DeleteProcThreadAttributeList(ptal);
            HeapFree(GetProcessHeap(), 0, ptal);
            return false;
        }

        siex.lpAttributeList = ptal;

        // Prepare command line (CreateProcessW requires modifiable string)
        std::wstring fullCommandLine = L"\"" + executablePath + L"\"";
        if (!commandLine.empty()) {
            fullCommandLine += L" " + commandLine;
        }

        std::vector<wchar_t> cmdLineBuffer(fullCommandLine.begin(), fullCommandLine.end());
        cmdLineBuffer.push_back(L'\0');

        // Create process with PPL protection
        if (!CreateProcessW(
            executablePath.c_str(),    // Application name
            cmdLineBuffer.data(),      // Command line
            nullptr,                   // Process security attributes
            nullptr,                   // Thread security attributes
            FALSE,                     // Inherit handles
            EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
            nullptr,                   // Environment
            nullptr,                   // Current directory
            &siex.StartupInfo,         // Startup info
            &pi))                       // Process information
        {
            std::wcerr << L"CreateProcessW failed: " << GetLastError() << std::endl;
            DeleteProcThreadAttributeList(ptal);
            HeapFree(GetProcessHeap(), 0, ptal);
            return false;
        }

        // Clean up attribute list
        DeleteProcThreadAttributeList(ptal);
        HeapFree(GetProcessHeap(), 0, ptal);

        m_hProcess = pi.hProcess;
        m_hThread = pi.hThread;

        std::wcout << L"Successfully created PPL process with PID: " << pi.dwProcessId << std::endl;
        std::wcerr << L"Protection level: " << GetPPLProtectionLevelName(GetPPLProtectionLevel(pi.dwProcessId)) << std::endl;
        return true;
    }

    bool WaitForProcess(DWORD timeout = INFINITE)
    {
        if (!m_hProcess) return false;

        DWORD result = WaitForSingleObject(m_hProcess, timeout);
        if (result == WAIT_OBJECT_0) {
            DWORD exitCode;
            if (GetExitCodeProcess(m_hProcess, &exitCode)) {
                std::wcout << L"Process exited with code: " << exitCode << std::endl;
            }
            return true;
        }

        return false;
    }

    HANDLE GetProcessHandle() const { return m_hProcess; }
    HANDLE GetThreadHandle() const { return m_hThread; }
};

// Function to check if we have sufficient privileges
bool CheckPrivileges()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        return false;
    }

    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    bool isElevated = false;

    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
    {
        isElevated = elevation.TokenIsElevated;
    }

    CloseHandle(hToken);
    return isElevated;
}

int wmain(int argc, wchar_t* argv[])
{
    std::wcout << L"\nPPL Process Creator" << std::endl;
    std::wcout << L"Two Seven One Three: x.com/TwoSevenOneT" << std::endl;
    std::wcout << L"==================================================" << std::endl << std::endl;
    //

    // Check if running with sufficient privileges
    if (!CheckPrivileges())
    {
        std::wcerr << L"Error: This program requires elevated privileges (Run as Administrator)" << std::endl;
        return 1;
    }

    if (argc < 3)
    {
        std::wcout << L"Usage: " << argv[0] << L"[mode:0-4] <executable_path> [command_line_args]" << std::endl << std::endl;
        std::wcout << L"Example: " << argv[0] << L" 1 \"C:\\Windows\\System32\\PPL.exe\"" << std::endl << std::endl;
        std::wcout << L"MODE: " << std::endl;
        std::wcout << L"PROTECTION_LEVEL_WINTCB_LIGHT       00000000" << std::endl;
        std::wcout << L"PROTECTION_LEVEL_WINDOWS            00000001" << std::endl;
        std::wcout << L"PROTECTION_LEVEL_WINDOWS_LIGHT      00000002" << std::endl;
        std::wcout << L"PROTECTION_LEVEL_ANTIMALWARE_LIGHT  00000003" << std::endl;
        std::wcout << L"PROTECTION_LEVEL_LSA_LIGHT          00000004" << std::endl;
        return 1;
    }
    //#define PROTECTION_LEVEL_WINTCB_LIGHT       0x00000000
    //#define PROTECTION_LEVEL_WINDOWS            0x00000001
    //#define PROTECTION_LEVEL_WINDOWS_LIGHT      0x00000002
    //#define PROTECTION_LEVEL_ANTIMALWARE_LIGHT  0x00000003
    //#define PROTECTION_LEVEL_LSA_LIGHT          0x00000004
    wchar_t* end;
    long value = wcstol(argv[1], &end, 10);
    DWORD protectionLevel = PROTECTION_LEVEL_ANTIMALWARE_LIGHT;
    switch (value)
    {
    case 0:
    {
        protectionLevel = PROTECTION_LEVEL_WINTCB_LIGHT;
        break;
    }
    case 1:
    {
        protectionLevel = PROTECTION_LEVEL_WINDOWS;
        break;
    }
    case 2:
    {
        protectionLevel = PROTECTION_LEVEL_WINDOWS_LIGHT;
        break;
    }
    case 4:
    {
        protectionLevel = PROTECTION_LEVEL_LSA_LIGHT;
        break;
    }
    default:
        break;
    }

    PPLProcessCreator creator;
    std::wstring executablePath = argv[2];
    std::wstring commandLine;

    // Build command line from remaining arguments
    for (int i = 3; i < argc; ++i)
    {
        if (!commandLine.empty())
        {
            commandLine += L" ";
        }
        commandLine += argv[i];
    }

    // Create the PPL process
    if (creator.CreatePPLProcess(protectionLevel, executablePath, commandLine))
    {
        std::wcout << L"Process created successfully. Waiting for completion..." << std::endl;
        creator.WaitForProcess();
        return 0;
    }
    else
    {
        std::wcerr << L"Failed to create PPL process." << std::endl;
        return 1;
    }
}
