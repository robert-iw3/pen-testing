// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include <string>

struct RunMeArgs {
    const wchar_t* arg1;
    const wchar_t* arg2;
};

extern "C" __declspec(dllexport) DWORD RunMe(RunMeArgs* args)
{
    std::wstring str1(args->arg1);
    std::wstring str2(args->arg2);
    OutputDebugString(str1.c_str());
    OutputDebugString(str2.c_str());

    if (str2.length() > 1)
    {
        BOOL result = CopyFileW(
            str1.c_str(),   // Existing file name
            str2.c_str(),     // New file name
            FALSE         // Overwrite if exists (FALSE = allow overwrite)
        );
        if (!result)
        {
            return GetLastError();
        }
        return 0;
    }
    HANDLE hFile = CreateFileW(
        str1.c_str(),                // File name
        GENERIC_WRITE,          // Desired access
        0,                      // Share mode
        NULL,                   // Security attributes
        CREATE_ALWAYS,          // Creation disposition
        FILE_ATTRIBUTE_NORMAL,  // Flags and attributes
        NULL                    // Template file
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        //OutputDebugString(L"Failed to create file");
        return GetLastError();
    }
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        OutputDebugString(L"DLL_PROCESS_ATTACH");
        break;
    }
    case DLL_THREAD_ATTACH:
    {
        OutputDebugString(L"DLL_THREAD_ATTACH");
        break;
    }
    case DLL_THREAD_DETACH:
    {
        OutputDebugString(L"DLL_THREAD_DETACH");
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        OutputDebugString(L"DLL_PROCESS_DETACH");
        break;
    }
    //
    }
    return TRUE;
}

