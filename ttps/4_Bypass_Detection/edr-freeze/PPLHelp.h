#pragma once
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

    DWORD GetPPLProtectionLevel(DWORD processId);
    std::wstring GetPPLProtectionLevelName(DWORD protectionLevel);
    DWORD CreatePPLProcess(DWORD protectionLevel, std::wstring& commandLine);

    HANDLE GetProcessHandle();
    HANDLE GetThreadHandle();
};

