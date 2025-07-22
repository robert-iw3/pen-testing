#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <tchar.h>
#include <stdio.h>

void ConvertUnicodeStringToChar(const wchar_t* src, size_t srcSize, char* dst, size_t dstSize)
{
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, src, (int)srcSize, dst, (int)dstSize, NULL, NULL);
    dst[dstSize - 1] = '\0';
}

void getEnvs() {
    LPWSTR lpszVariable;
    LPWCH lpvEnv;


    // Get a pointer to the environment block.
    //lpvEnv = KERNEL32$GetEnvironmentStrings();
    lpvEnv = KERNEL32$GetEnvironmentStringsW();

    internal_printf("Gathering Process Environment Variables:\n\n");

    // If the returned pointer is NULL, exit.
    if (lpvEnv == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "GetEnvironmentStrings failed.");
        return;
    }

    // Variable strings are separated by NULL byte, and the block is
    // terminated by a NULL byte.
    lpszVariable = (LPWSTR) lpvEnv;

    while (*lpszVariable)
    {
        SIZE_T envLength = KERNEL32$lstrlenW(lpszVariable);
        char * convertedEnv = intAlloc(envLength + 1);
        ConvertUnicodeStringToChar(lpszVariable, envLength + 1, convertedEnv, envLength + 1);
        internal_printf("%s\n", convertedEnv);
        lpszVariable += KERNEL32$lstrlenW(lpszVariable) + 1;
        intFree(convertedEnv);
    }
    return;
}

VOID go()
{

    if(!bofstart())
    {
        return;
    }

    getEnvs();

    printoutput(TRUE);
    bofstop();
};