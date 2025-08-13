
#include "common.h"
#include "windows.h"

BOOL WriteFileW(IN LPCWSTR wszFileName, IN PBYTE pbFileContent, IN DWORD dwFileSize) {

    BOOL    bSTATE      = TRUE;
    HANDLE  hFile       = NULL;

    // Create a file
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
    hFile = CreateFileW(
        wszFileName,            // Name of the file
        GENERIC_WRITE,          // Write permissions
        0,                      // Dont share
        NULL,                   // Optional can be NULL
        CREATE_ALWAYS,          // Always creates a new file
        FILE_ATTRIBUTE_NORMAL,  // The file does not have other attributes set.
        NULL                    // Optional can be NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        errorWin32("CreateFileW - Failed to open file");
        bSTATE = FALSE;
        goto _cleanUp;
    }

    // Write data to the file
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
    if (!WriteFile(
        hFile,          // Handle to the file
        pbFileContent,  // Pointer to bytes to write
        dwFileSize,     // Size to write
        NULL,           // Optional can be NULL
        NULL            // Optional can be NULL
    )) {
        errorWin32("WriteFile - Failed to write data to file");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    
_cleanUp:

    // Cleanup close handle to file
    if (hFile) {
        CloseHandle(hFile);
    }
   
    return bSTATE;
}

BOOL RemoveFileW(IN LPCWSTR wszFileName) {
    
    BOOL    bSTATE = TRUE;
    HANDLE  hFile       = NULL;

    // Attempt to open the file (Check if the file exists)
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
    hFile = CreateFileW(
        wszFileName,            // Name of the file
        GENERIC_READ,           // Read permissions (just to check existence)
        0,                      // No sharing
        NULL,                   // Optional security attributes
        OPEN_EXISTING,          // Open the file if it exists
        FILE_ATTRIBUTE_NORMAL,  // Normal file attributes
        NULL                    // No template file
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        // If file doesn't exist, return false
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            errorW(L"file \"%s\" does not exist.", wszFileName);
            bSTATE = FALSE;
            goto _cleanUp;
        }
        else {
            errorWin32("CreateFileW - Failed to open file for removal");
            bSTATE = FALSE;
            goto _cleanUp;
        }
        return FALSE;
    }

    // Close handle to file before deletion
    if (hFile) {
        CloseHandle(hFile);
    }

    // File exists, attempt to delete it
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew
    if (!DeleteFileW(wszFileName)) {
        errorWin32("DeleteFileW - Failed to delete the file");
        bSTATE = FALSE;
        goto _cleanUp;
    }

_cleanUp:

    return bSTATE;
}
