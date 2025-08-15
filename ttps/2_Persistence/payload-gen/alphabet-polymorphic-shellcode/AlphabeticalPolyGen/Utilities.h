#ifndef UTILITIES_H
#define UTILITIES_H

#include <Windows.h>
#include <stdio.h>

// ============================================================================================================================================================
// ============================================================================================================================================================


BOOL ParseAndValidateCommandLine(OUT PWCHAR* ppwszInputFile, OUT PWCHAR* ppwszOutputFile)
{
    LPWSTR      pwszCommandLine         = NULL;
    INT         nArgc                   = 0x00;
    LPWSTR*     ppwszArgv               = NULL;
    DWORD       dwIndex                 = 0x00;
    DWORD       dwFileNameLength        = 0x00;
    DWORD       dwAttributes            = 0x00;
    PWCHAR      pwszInputPath           = NULL;
    PWCHAR      pwszOutputPath          = NULL;
    PWCHAR      pwszOutputDir           = NULL;
    PWCHAR      pwszLastSlash           = NULL;
    BOOL        bInputFound             = FALSE;
    BOOL        bOutputFound            = FALSE;
    BOOL        bResult                 = FALSE;

    if (!ppwszInputFile || !ppwszOutputFile)
    {
        return FALSE;
    }

    *ppwszInputFile     = NULL;
    *ppwszOutputFile    = NULL;

    pwszCommandLine = GetCommandLineW();
    if (!pwszCommandLine)
    {
        wprintf(L"[!] GetCommandLineW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    ppwszArgv = CommandLineToArgvW(pwszCommandLine, &nArgc);
    if (!ppwszArgv)
    {
        wprintf(L"[!] CommandLineToArgvW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    for (dwIndex = 1; dwIndex < (DWORD)nArgc; dwIndex++)
    {
        if (wcscmp(ppwszArgv[dwIndex], L"--i") == 0 || wcscmp(ppwszArgv[dwIndex], L"-i") == 0)
        {
            if (dwIndex + 1 >= (DWORD)nArgc)
            {
                wprintf(L"[!] Error: --i Flag Requires A Filename\n");
                goto _END_OF_FUNC;
            }

            if (bInputFound)
            {
                wprintf(L"[!] Error: Duplicate Input File Specification\n");
                goto _END_OF_FUNC;
            }

            dwFileNameLength    = (DWORD)(wcslen(ppwszArgv[dwIndex + 1]) + 1) * sizeof(WCHAR);
            pwszInputPath       = (PWCHAR)LocalAlloc(LPTR, dwFileNameLength);

            if (!pwszInputPath)
            {
                wprintf(L"[!] LocalAlloc Failed For Input Path With Error: %d\n", GetLastError());
                goto _END_OF_FUNC;
            }

            RtlCopyMemory(pwszInputPath, ppwszArgv[dwIndex + 1], dwFileNameLength);
            bInputFound = TRUE;
            dwIndex++; 
        }

        else if (wcscmp(ppwszArgv[dwIndex], L"--o") == 0 || wcscmp(ppwszArgv[dwIndex], L"-o") == 0)
        {
            if (dwIndex + 1 >= (DWORD)nArgc)
            {
                wprintf(L"[!] Error: --o Flag Requires A Filename\n");
                goto _END_OF_FUNC;
            }

            if (bOutputFound)
            {
                wprintf(L"[!] Error: Duplicate Output File Specification\n");
                goto _END_OF_FUNC;
            }

            dwFileNameLength    = (DWORD)(wcslen(ppwszArgv[dwIndex + 1]) + 1) * sizeof(WCHAR);
            pwszOutputPath      = (PWCHAR)LocalAlloc(LPTR, dwFileNameLength);

            if (!pwszOutputPath)
            {
                wprintf(L"[!] LocalAlloc Failed For Output Path With Error: %d\n", GetLastError());
                goto _END_OF_FUNC;
            }

            RtlCopyMemory(pwszOutputPath, ppwszArgv[dwIndex + 1], dwFileNameLength);
            bOutputFound = TRUE;
            dwIndex++; 
        }
    }

    if (!bInputFound && !bOutputFound)
    {
        wprintf(L"[!] No File Paths Specified\n");
        wprintf(L"[*] Usage: %s --i <input_file> --o <output_file>\n", ppwszArgv[0]);
        goto _END_OF_FUNC;
    }

    if (bInputFound)
    {
        dwAttributes = GetFileAttributesW(pwszInputPath);
        if (dwAttributes == INVALID_FILE_ATTRIBUTES)
        {
            wprintf(L"[!] Input File Does Not Exist: %s\n", pwszInputPath);
            wprintf(L"[!] GetFileAttributes Failed With Error: %d\n", GetLastError());
            goto _END_OF_FUNC;
        }

        if (dwAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            wprintf(L"[!] Input Path Is A Directory, Not A File: %s\n", pwszInputPath);
            goto _END_OF_FUNC;
        }

        wprintf(L"[+] Input File Validated: %s\n", pwszInputPath);
    }

    if (bOutputFound)
    {
        dwFileNameLength    = (DWORD)(wcslen(pwszOutputPath) + 1) * sizeof(WCHAR);
        pwszOutputDir       = (PWCHAR)LocalAlloc(LPTR, dwFileNameLength);

        if (!pwszOutputDir)
        {
            wprintf(L"[!] LocalAlloc Failed For Directory Path With Error: %d\n", GetLastError());
            goto _END_OF_FUNC;
        }

        RtlCopyMemory(pwszOutputDir, pwszOutputPath, dwFileNameLength);

        pwszLastSlash = wcsrchr(pwszOutputDir, L'\\');
        if (!pwszLastSlash)
        {
            pwszLastSlash = wcsrchr(pwszOutputDir, L'/');
        }

        if (pwszLastSlash)
        {
            *pwszLastSlash = L'\0'; 

            dwAttributes = GetFileAttributesW(pwszOutputDir);
            if (dwAttributes == INVALID_FILE_ATTRIBUTES)
            {
                wprintf(L"[!] Output Directory Does Not Exist: %s\n", pwszOutputDir);
                wprintf(L"[!] GetFileAttributes Failed With Error: %d\n", GetLastError());
                goto _END_OF_FUNC;
            }

            if (!(dwAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                wprintf(L"[!] Output Path Parent Is Not A Directory: %s\n", pwszOutputDir);
                goto _END_OF_FUNC;
            }
        }

        if ((dwAttributes = GetFileAttributesW(pwszOutputPath)) != INVALID_FILE_ATTRIBUTES)
        {
            if (dwAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                wprintf(L"[!] Output Path Is An Existing Directory: %s\n", pwszOutputPath);
                goto _END_OF_FUNC;
            }
            wprintf(L"[*] Warning: Output File Already Exists And Will Be Overwritten: %s\n", pwszOutputPath);
        }

        wprintf(L"[+] Output Path Validated: %s\n", pwszOutputPath);
    }

    *ppwszInputFile     = pwszInputPath;
    *ppwszOutputFile    = pwszOutputPath;
    pwszInputPath       = NULL;  
    pwszOutputPath      = NULL; 
    bResult             = TRUE;

_END_OF_FUNC:
    if (pwszInputPath)
    {
        RtlZeroMemory(pwszInputPath, wcslen(pwszInputPath) * sizeof(WCHAR));
        LocalFree(pwszInputPath);
        pwszInputPath = NULL;
    }
    if (pwszOutputPath)
    {
        RtlZeroMemory(pwszOutputPath, wcslen(pwszOutputPath) * sizeof(WCHAR));
        LocalFree(pwszOutputPath);
        pwszOutputPath = NULL;
    }
    if (pwszOutputDir)
    {
        RtlZeroMemory(pwszOutputDir, wcslen(pwszOutputDir) * sizeof(WCHAR));
        LocalFree(pwszOutputDir);
        pwszOutputDir = NULL;
    }
    if (ppwszArgv)
    {
        LocalFree(ppwszArgv);
        ppwszArgv = NULL;
    }
    return bResult;
}

// ============================================================================================================================================================
// ============================================================================================================================================================


BOOL ReadFileFromDiskW(IN LPCWSTR szFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE		    hFile					= INVALID_HANDLE_VALUE;
    LARGE_INTEGER   liFileSize			    = { 0 };
	DWORD		    dwNumberOfBytesRead		= NULL;
	PBYTE		    pBaseAddress			= NULL;

    if (!szFileName || !pdwFileSize || !ppFileBuffer)
        return FALSE;

	*ppFileBuffer   = NULL;
	*pdwFileSize    = 0x00;

	if ((hFile = CreateFileW(szFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) 
    {
        printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
	}

	if (!GetFileSizeEx(hFile, &liFileSize))
    {
        printf("[!] GetFileSizeEx [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pBaseAddress = (PBYTE)LocalAlloc(LPTR, liFileSize.QuadPart))) 
    {
		printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hFile, pBaseAddress, liFileSize.QuadPart, &dwNumberOfBytesRead, NULL) || (DWORD)liFileSize.QuadPart != dwNumberOfBytesRead) 
    {
		printf("[!] ReadFile Failed With Error: %d \n[i] Read %ld Of %ld Bytes \n", GetLastError(), dwNumberOfBytesRead, (DWORD)liFileSize.QuadPart);
		goto _END_OF_FUNC;
	}

	*ppFileBuffer = pBaseAddress;
	*pdwFileSize  = (DWORD)liFileSize.QuadPart;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pBaseAddress && !*ppFileBuffer)
		LocalFree(pBaseAddress);
	return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}

// ============================================================================================================================================================
// ============================================================================================================================================================


BOOL WriteFileToDiskW(IN LPCWSTR szFileName, IN PBYTE pFileBuffer, OUT DWORD dwFileSize) 
{
    HANDLE		hFile                   = INVALID_HANDLE_VALUE;
    DWORD		dwNumberOfBytesWritten  = 0x00;

    if (!szFileName || !pFileBuffer || !dwFileSize)
		return FALSE;

    if ((hFile = CreateFileW(szFileName, GENERIC_READ | GENERIC_WRITE, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) 
    {
        printf("[!] WriteFile Failed With Error: %d \n[i] Wrote %ld Of %ld Bytes \n", GetLastError(), dwNumberOfBytesWritten, dwFileSize);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    return (dwNumberOfBytesWritten == dwFileSize) ? TRUE : FALSE;
}


// ============================================================================================================================================================
// ============================================================================================================================================================

VOID HexDump(IN LPCWSTR szName, IN PBYTE pBuffer, IN DWORD dwBufferLength)
{
    DWORD dwIndex = 0x00;

    wprintf(L"\n[*] %s [%ld] Hex Ascii Dump:\n", szName, dwBufferLength);
    wprintf(L"[*] Address\t\tHex\t\tAscii\n");
    wprintf(L"[*] ----------------------------------------\n");

    for (dwIndex = 0x00; dwIndex < dwBufferLength; dwIndex++) {
        if ((dwIndex % 16) == 0) {
            wprintf(L"[*] 0x%08X\t", dwIndex);
        }
        wprintf(L"%02X ", pBuffer[dwIndex]);
        if ((dwIndex % 16) == 15) {
            wprintf(L"\t");
            for (DWORD i = dwIndex - 15; i <= dwIndex; i++) {
                if (pBuffer[i] >= 0x20 && pBuffer[i] <= 0x7E) {
                    wprintf(L"%c", pBuffer[i]);
                }
                else {
                    wprintf(L".");
                }
            }
            wprintf(L"\n");
        }
    }
    if ((dwIndex % 16) != 0) {
        wprintf(L"\n");
    }
}

// ============================================================================================================================================================
// ============================================================================================================================================================


VOID HexDump1(IN LPCWSTR szName, IN PBYTE pBuffer, IN DWORD dwBufferLength)
{
    DWORD dwIndex = 0x00;

    wprintf(L"[i] Printing C-Array of %s [%ld] Bytes:\n\n", szName ? szName : L"(null)", dwBufferLength);

    if (!pBuffer || !dwBufferLength) {
        wprintf(L"\n[*] %s: Empty Buffer\n", szName ? szName : L"(null)");
        return;
    }

    wprintf(L"unsigned char %ls[%lu] = {\n    ", szName ? szName : L"Buffer", (unsigned long)dwBufferLength);

    for (dwIndex = 0; dwIndex < dwBufferLength; ++dwIndex) 
    {
        wprintf(L"0x%02X", pBuffer[dwIndex]);

        if (dwIndex + 1 != dwBufferLength)
            wprintf(L", ");

        if (((dwIndex + 1) % 0x10) == 0 && (dwIndex + 1) < dwBufferLength)
            wprintf(L"\n    ");
    }

    wprintf(L"\n};\n");
}



// ============================================================================================================================================================



#endif // !UTILITIES_H
