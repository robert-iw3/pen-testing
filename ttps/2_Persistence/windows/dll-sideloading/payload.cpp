#include "payload.h"

DWORD WINAPI PayloadThread(LPVOID lpParam) {
    Sleep(2000);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    wchar_t cmd[] = L"cmd.exe /c notepad.exe";

    BOOL success = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    if (!success) {
        DWORD errorCode = GetLastError();

        HANDLE hFile = CreateFileW(L"C:\\Users\\Public\\log.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            wchar_t buffer[256];
            DWORD bytesWritten;
            wsprintfW(buffer, L"CreateProcessW failed with error code: %lu", errorCode);
            WriteFile(hFile, buffer, lstrlenW(buffer) * sizeof(wchar_t), &bytesWritten, NULL);
            CloseHandle(hFile);
        }
    }
    else {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return 0;
}