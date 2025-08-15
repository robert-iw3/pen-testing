#include <Windows.h>
#include <stdio.h>


BOOL ReadInputFileFromCommandLine(OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize)
{
    LPWSTR          pwszCommandLine         = NULL;
    INT             nArgc                   = 0x00;
    LPWSTR*         ppwszArgv               = NULL;
    DWORD           dwIndex                 = 0x00;
    DWORD           dwAttributes            = 0x00;
    PWCHAR          pwszInputPath           = NULL;
    HANDLE          hFile                   = INVALID_HANDLE_VALUE;
    LARGE_INTEGER   liFileSize              = { 0 };
    DWORD           dwNumberOfBytesRead     = 0x00;
    PBYTE           pBaseAddress            = NULL;
    BOOL            bInputFound             = FALSE;
    BOOL            bResult                 = FALSE;

    if (!ppFileBuffer || !pdwFileSize)
    {
        return FALSE;
    }

    *ppFileBuffer   = NULL;
    *pdwFileSize    = 0x00;

    if (!(pwszCommandLine = GetCommandLineW()))
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

            pwszInputPath = ppwszArgv[dwIndex + 1];
            bInputFound = TRUE;
            dwIndex++;
        }
    }

    if (!bInputFound)
    {
        wprintf(L"[!] No Input File Specified\n");
        wprintf(L"[*] Usage: %s --i <input_file>\n", ppwszArgv[0]);
        goto _END_OF_FUNC;
    }

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

    hFile = CreateFileW(
        pwszInputPath,
        GENERIC_READ,
        0x00,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[!] CreateFileW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!GetFileSizeEx(hFile, &liFileSize))
    {
        wprintf(L"[!] GetFileSizeEx Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (liFileSize.QuadPart == 0x00)
    {
        wprintf(L"[!] Input File Is Empty: %s\n", pwszInputPath);
        goto _END_OF_FUNC;
    }

    if (liFileSize.QuadPart > 0xFFFFFFFF)
    {
        wprintf(L"[!] Input File Too Large: %lld Bytes\n", liFileSize.QuadPart);
        goto _END_OF_FUNC;
    }

    pBaseAddress = (PBYTE)LocalAlloc(LPTR, liFileSize.QuadPart);
    if (!pBaseAddress)
    {
        wprintf(L"[!] LocalAlloc Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ReadFile(hFile, pBaseAddress, (DWORD)liFileSize.QuadPart, &dwNumberOfBytesRead, NULL))
    {
        wprintf(L"[!] ReadFile Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((DWORD)liFileSize.QuadPart != dwNumberOfBytesRead)
    {
        wprintf(L"[!] Partial Read: Read %d Of %d Bytes\n", dwNumberOfBytesRead, (DWORD)liFileSize.QuadPart);
        goto _END_OF_FUNC;
    }

    wprintf(L"[+] Successfully Read %d Bytes From File\n", dwNumberOfBytesRead);

    *ppFileBuffer   = pBaseAddress;
    *pdwFileSize    = (DWORD)liFileSize.QuadPart;
    pBaseAddress    = NULL;
    bResult         = TRUE;

_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    if (pBaseAddress && !*ppFileBuffer)
    {
        RtlZeroMemory(pBaseAddress, liFileSize.QuadPart);
        LocalFree(pBaseAddress);
        pBaseAddress = NULL;
    }
    if (ppwszArgv)
    {
        LocalFree(ppwszArgv);
        ppwszArgv = NULL;
    }

    return bResult;
}



int wmain()
{
    PBYTE       pFileBuffer     = NULL,
                pExecBuffer     = NULL;
    DWORD       dwFileSize      = 0x00;
    HANDLE	    hThread         = NULL;

    if (!ReadInputFileFromCommandLine(&pFileBuffer, &dwFileSize))
        return -1;

    wprintf(L"[i] File Size: %d Bytes\n", dwFileSize);
    wprintf(L"[i] Buffer Address: 0x%p\n", pFileBuffer);

    if (dwFileSize >= 16)
    {
        wprintf(L"[*] First 16 Bytes: ");
        for (DWORD i = 0; i < 16; i++)
        {
            wprintf(L"%02X ", pFileBuffer[i]);
        }
        wprintf(L"\n");
    }

	if (!(pExecBuffer = (PBYTE)VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
    {
        wprintf(L"[!] VirtualAlloc Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
	}

    RtlCopyMemory(pExecBuffer, pFileBuffer, dwFileSize);

    wprintf(L"[*] Executable Buffer Address: 0x%p\n", pExecBuffer);

	if (!(hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pExecBuffer, NULL, 0, NULL)))
    {
        wprintf(L"[!] CreateThread Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
	}

	WaitForSingleObject(hThread, INFINITE);

_END_OF_FUNC:
    if (pExecBuffer)
    {
		VirtualFree(pExecBuffer, 0, MEM_RELEASE);
		pExecBuffer = NULL;
    }
    if (pFileBuffer)
    {
        LocalFree(pFileBuffer);
        pFileBuffer = NULL;
    }

    return 0;
}