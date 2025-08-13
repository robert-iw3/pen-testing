#include "common.h"

// Read file from disk
// Function from hellshell
BOOL ReadPayloadFile(IN const char* FileInput, OUT PDWORD pdwPayloadSize, OUT unsigned char** pPayloadData) {

	BOOL	bSTATE = TRUE;
	HANDLE	hFile = NULL; // Handle to file
	DWORD	dwFileSize = NULL; // Stores size of file
	LPVOID	pPayload = NULL; // Stores pointer to the payload 
	DWORD	lpNumberOfBytesRead = NULL; // Stores number of bytes read

	// Open handle to file on disk
	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
	hFile = CreateFileA(
		FileInput,				// Name of the ifle
		GENERIC_READ,			// Request read permissions
		0,						// Prevents other processes from opening a file or device if they request delete, read, or write access. 
		NULL,					// Optional can be NULL
		OPEN_EXISTING,			// Opens a file or device, only if it exists. 
		FILE_ATTRIBUTE_NORMAL,	// Common default value for file
		NULL					// Can be NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		errorWin32("CreateFileA - Failed to open handle to file");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("CreateFileA - Received handle to file 0x%p", hFile);

	// Get size of the file
	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize
	dwFileSize = GetFileSize(
		hFile,	// Handle to file
		NULL	// Can be NULL
	);
	if (dwFileSize == NULL) {
		errorWin32("GetFileSize - Failed to get size of file");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("GetFileSize - Filesize is %d bytes", dwFileSize);

	// Allocate memory
	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
	pPayload = VirtualAlloc(
		NULL,						// Let the system determines where to allocate the region.
		dwFileSize,					// Size of memory to allocate
		MEM_COMMIT | MEM_RESERVE,	// Commit and reserve memory
		PAGE_READWRITE				// RW memory
	);
	if (pPayload == NULL) {
		errorWin32("VirtualAlloc - Failed to allocate memory");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("VirtualAlloc - Allocated %d bytes of memory", dwFileSize);

	// Read the file
	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
	if (!ReadFile(
		hFile,					// Handle to the file
		pPayload,				// Handle to memory which saves the file
		dwFileSize,				// Bytes to read
		&lpNumberOfBytesRead,	// Bytes read
		NULL					// Can be NULL
	)) {
		errorWin32("ReadFile - Failed to read the file");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("ReadFile - Read %d bytes", lpNumberOfBytesRead);

	// Check if any of the values are null
	if (pPayload == NULL || lpNumberOfBytesRead == NULL) {
		error("pPayload or lpNumberOfBytesRead is NULL");
		bSTATE = FALSE;
		goto _cleanUp;
	}

	// Give back the values to calling function
	*pPayloadData = pPayload;
	*pdwPayloadSize = lpNumberOfBytesRead;

_cleanUp:

	if (hFile) {
		CloseHandle(hFile);
	}

	return bSTATE;
}