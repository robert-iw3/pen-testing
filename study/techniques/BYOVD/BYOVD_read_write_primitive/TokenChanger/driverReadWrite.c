#include "common.h"

DWORD ReadMemoryPrimitive(IN HANDLE hDevice, IN DWORD dwSize, IN DWORD64 dwAddress) {
    
    RTCORE64_MEMORY_READ    memoryRead          = { 0 };    // Initialize struct with 0
    BOOL                    bSuccess            = NULL;     // Save the DeviceIOControl status
    DWORD                   dwBytesReturned     = NULL;     // Amount of bytes returned
    
    // Set the address to read
    memoryRead.Address = dwAddress;

    // Set the amount of bytes to read
    memoryRead.ReadSize = dwSize;

    // Sends control code directly to device driver
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
        error("DeviceIoControl - failed to read bytes");
        return FALSE;
    }

    return memoryRead.Value;
}

// Writes a DWORD value to a given address using the RTCore64 driver
BOOL WriteMemoryPrimitive(IN HANDLE hDevice, IN DWORD dwSize, IN DWORD64 dwAddress, IN DWORD dwValue) {

    RTCORE64_MEMORY_WRITE   memoryWrite     = { 0 };    // Initialize struct with 0
    BOOL                    bSuccess        = NULL;     // Save the DeviceIOControl status
    DWORD                   dwBytesReturned = NULL;     // Amount of bytes returned

    // Set the address to read
    memoryWrite.Address = dwAddress;

    // Set the amount of bytes to read
    memoryWrite.WriteSize = dwSize;

    // Set the value to write
    memoryWrite.Value = dwValue;

    // Sends control code directly to device driver
    // https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol
    bSuccess = DeviceIoControl(
        hDevice,					// Handle to the device
        RTCORE64_MEMORY_WRITE_CODE,	// IOCTL Code that specifies the operation
        &memoryWrite,				// Pointer to input data
        sizeof(memoryWrite),		// Size of data
        &memoryWrite,				// Output buffer
        sizeof(memoryWrite),		// Size of the output buffer
        &dwBytesReturned,			// Number of bytes returned
        NULL						// Overlapped structure
    );
    if (!bSuccess) {
        error("DeviceIoControl - failed to write bytes");
        return FALSE;
    }

    return TRUE;
}

// Helper function to read 1 bytes
BYTE ReadMemoryBYTE(IN HANDLE Device, IN DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 1, Address) & 0xffffff;
}

// Helper function to read 2 bytes (WORD)
WORD ReadMemoryWORD(IN HANDLE Device, IN DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
}

// Helper function to read 4 bytes (DWORD)
DWORD ReadMemoryDWORD(IN HANDLE Device, IN DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address);
}

// Helper function to read 8 bytes (DWORD64)
DWORD64 ReadMemoryDWORD64(IN HANDLE Device, IN DWORD64 Address) {
    
    // Read the lower 4 bytes
    DWORD dwLow = ReadMemoryDWORD(Device, Address);

    // Read the upper 4 bytes
    DWORD dwHigh = ReadMemoryDWORD(Device, Address + 4);        

    // Combine the high and low parts into a 64-bit value
    return ((DWORD64)dwHigh << 32) | dwLow;                 
}


// Writes a DWORD64 (8 bytes) to the target memory address
void WriteMemoryDWORD64(IN HANDLE Device, IN DWORD64 Address, IN DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}