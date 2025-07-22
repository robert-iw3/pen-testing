#pragma once
#include <Windows.h>

class TimeStomper {
public:
    static VOID StompFile(LPCWSTR path) {
        HANDLE hFile = CreateFileW(path, FILE_WRITE_ATTRIBUTES, 
                                  FILE_SHARE_READ, NULL, 
                                  OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            SetFileTime(hFile, &ft, &ft, &ft);
            CloseHandle(hFile);
        }
    }

    static VOID RandomizeTimestamps(HANDLE hFile) {
        FILETIME ft;
        SYSTEMTIME st;
        GetSystemTime(&st);
        st.wYear = 1990 + (rand() % 30);
        st.wMonth = 1 + (rand() % 12);
        SystemTimeToFileTime(&st, &ft);
        SetFileTime(hFile, &ft, &ft, &ft);
    }
};

class MemoryWiper {
public:
    __forceinline static VOID SecureErase(PVOID addr, SIZE_T len) {
        volatile BYTE* p = static_cast<volatile BYTE*>(addr);
        while (len--) *p++ = rand() % 256;
        __faststorefence();
    }
};
