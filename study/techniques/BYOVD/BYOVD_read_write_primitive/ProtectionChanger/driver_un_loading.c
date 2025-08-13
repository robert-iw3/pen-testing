#include "common.h"

BOOL GenerateDriverFullPath(IN LPWSTR pszDriverName, IN size_t cchDriverPath, OUT WCHAR* pszDriverPath) {

    BOOL bSTATE = TRUE;

    // Check if something is NULL
    if (pszDriverName == NULL || pszDriverPath == NULL || cchDriverPath == NULL) {
        error("LoadDriver - Something is null");
        bSTATE = FALSE;
        goto _cleanUp;
    }

    WCHAR szWinPath[MAX_PATH] = { 0 }; // Stores the path to the Windows directory

    // Get the path of the windows directory (C:\Windows)
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectoryw
    if (GetWindowsDirectoryW(
        szWinPath,            // Pointer to buffer which stores the LPWSTR buffer
        _countof(szWinPath)   // Max size of the buffer
    ) == 0) {
        errorWin32("GetWindowsDirectoryW - Failed to get path of windows directory");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    infoW_t(L"GetWindowsDirectoryW - Windows path \"%s\"", szWinPath);

    // Build "<SystemRoot>\\System32\\drivers\\pszDriverName"
    int n = swprintf_s(
        pszDriverPath,          // Store the location in here 
        cchDriverPath,          // Size of destination buffer in WCHARs
        L"%ls%ls%ls",           // Format: <WindowsPath> + <VULNDRIVERPATH> + <DriverName>
        szWinPath,              // Input <WindowsPath>
        g_VULNDRIVERPATH,       // Input rest of the driver path
        pszDriverName           // Input driver name
    );
    if (n < 0) {
        error("swprintf_s - Failed to build driver path");
        bSTATE = FALSE;
        goto _cleanUp;
    }

_cleanUp:

    return bSTATE;

}


BOOL WriteDriverToFile(IN LPWSTR pszDriverName, IN PBYTE pbDriver, IN DWORD dwDriverSize, OUT LPWSTR* pszFullDriverPath) {

    BOOL bSTATE = TRUE;

    // Check if something is NULL
    if (pszDriverName == NULL || pbDriver == NULL || dwDriverSize == NULL) {
        error("LoadDriver - Something is null");
        bSTATE = FALSE;
        goto _cleanUp;
    }

    WCHAR*  szVulnDriverPath            = NULL;
    WCHAR   szDriverPath[MAX_PATH]      = { 0 };  // Buffer to receive the full driver path

    // Allocate memory for saving the the full vulnerable driver path
    szVulnDriverPath = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));  // Allocate memory dynamically
    if (szVulnDriverPath == NULL) {
        error("Malloc - Memory allocation failed for fullDriverPath");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("malloc - Allocated %d bytes of memory for driver path at 0x%p", MAX_PATH * sizeof(WCHAR), szVulnDriverPath);

    // Generate driver path by calling the function
    info_t("GenerateDriverFullPath - Genereting driver directory");
    if (!GenerateDriverFullPath(pszDriverName, _countof(szDriverPath), szDriverPath)) {
        error("GenerateDriverFullPath - Failed to generate full driver path");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    infoW_t("Generated driver directory \"%s\"", szDriverPath);

    if (!WriteFileW(szDriverPath, pbDriver, dwDriverSize)) {
        error("WriteFileW - Failed to write driver");
        bSTATE = FALSE;
        goto _cleanUp;
    }

    wcscpy_s(szVulnDriverPath, MAX_PATH, szDriverPath);
    *pszFullDriverPath = szVulnDriverPath;

_cleanUp:

    return bSTATE;
}


BOOL LoadDriver(IN LPCWSTR lpwcDriverName, IN LPCWSTR lpwcDriverPath) {

    BOOL        bSTATE      = TRUE;
    SC_HANDLE   hScm        = NULL; // Stores handle to the SCManager
    SC_HANDLE   hService    = NULL; // Stores handle to the registered service

    // Check if something is NULL
    if (lpwcDriverName == NULL || lpwcDriverPath == NULL) {
        error("LoadDriver - Something is null");
        bSTATE = FALSE;
        goto _cleanUp;
    }

    // Establish connection to the service control manager
    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw
    hScm = OpenSCManagerW(
        NULL,                       // Connect to the local computer
        SERVICES_ACTIVE_DATABASE,   // Default value
        SC_MANAGER_CREATE_SERVICE   // Access rights to create service
    );
    if (hScm == NULL) {
        errorWin32("OpenSCManagerW - Failed to open Service Control Manager");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("Retrieved handle to control manager 0x%p", hScm);

    // Create the service for the driver
    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew
    hService = CreateServiceW(
        hScm,                                       // Handle to the SCM manager
        lpwcDriverName,                             // Service name
        lpwcDriverName,                             // Display name
        SERVICE_START,                              // Permissions to start the service
        SERVICE_KERNEL_DRIVER,                      // Service type
        SERVICE_DEMAND_START,                       // Start type
        SERVICE_ERROR_IGNORE,                       // The startup program ignores the error and continues the startup operation. 
        lpwcDriverPath,                             // Path to driver file
        NULL,                                       // Optional can be NULL
        NULL,                                       // Optional can be NULL
        NULL,                                       // Optional can be NULL
        NULL,                                       // Optional can be NULL
        NULL                                        // Optional can be NULL
    );
    if (hService == NULL) {
        
        // Handle case where driver already exists
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            info_t("CreateServiceW - Failed service already registered, attempting to start");

            // Open handle to existing service
            // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicew
            hService = OpenServiceW(
                hScm,               // Handle to the SCM manager
                lpwcDriverName,     // The name of the service to be opened
                SERVICE_START       // Request service start
            );
            if (hService == NULL) {
                errorWin32("OpenServiceW - Failed to open service");
                bSTATE = FALSE;
                goto _cleanUp;
            }

        }
        else {
            errorWin32("CreateServiceW - Failed to create service");
            bSTATE = FALSE;
            goto _cleanUp;
        }
    }
    info_t("CreateServiceW / OpenServiceW - Retrieved handle to service 0x%p", hService);

    // Start the driver
    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew
    if (!StartServiceW(
        hService,   // Handle to service
        0,          // Can be 0
        NULL        // Optional can be null
    )) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_SERVICE_ALREADY_RUNNING) {
            info_t("StartServiceW - Driver already running");
        }
        else {
            errorWin32("StartServiceW - Failed to start service.");
            bSTATE = FALSE;
            goto _cleanUp;
        }
    }
    else {
        info_t("StartServiceW - Driver started", hService);
    }

_cleanUp:

    // Close handles to the service and SCM
    if (hService) {
        CloseServiceHandle(hService);
    }
    if (hScm) {
        CloseServiceHandle(hScm);
    }

    return bSTATE;
}


BOOL UnloadDriver(IN LPCWSTR lpwcDriverName) {

    BOOL            bSTATE = TRUE;
    SC_HANDLE       hScm = NULL;     // Stores handle to the SCManager
    SC_HANDLE       hService = NULL;     // Stores handle to the registered service
    SERVICE_STATUS  status = { 0 };    // Stores the status of the service
    BOOL            bStoppedOrAlreadyStopped = FALSE;

    // Check if something is NULL
    if (lpwcDriverName == NULL) {
        error("LoadDriver - Something is null");
        bSTATE = FALSE;
        goto _cleanUp;
    }

    // Establish connection to the service control manager
    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw
    hScm = OpenSCManagerW(
        NULL,                       // Connect to the local computer
        SERVICES_ACTIVE_DATABASE,   // Default value
        SC_MANAGER_CREATE_SERVICE   // Access rights to create service
    );
    if (hScm == NULL) {
        errorWin32("OpenSCManagerW - Failed to open Service Control Manager");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("Retrieved handle to control manager 0x%p", hScm);

    // Open handle to existing service
    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicew
    hService = OpenServiceW(
        hScm,                   // Handle to the SCM manager
        lpwcDriverName,         // The name of the service to be opened
        SERVICE_STOP | DELETE   // Request service stop and delete permissions
    );
    if (hService == NULL) {
        errorWin32("OpenServiceW - Failed to open service");
        bSTATE = FALSE;
        goto _cleanUp;
    }
    info_t("OpenServiceW - Retrieved handle to service 0x%p", hService);

    // Stop the service
    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice
    if (!ControlService(
        hService,               // Handle to the service
        SERVICE_CONTROL_STOP,   // Stop the service
        &status                 // Output most recent status
    )) {
        DWORD dwErr = GetLastError();
        if (dwErr == ERROR_SERVICE_NOT_ACTIVE) {
            info_t("ControlService - Service is already stopped");
            bStoppedOrAlreadyStopped = TRUE;
        }
        else {
            errorWin32("ControlService - Failed to stop service");
            bSTATE = FALSE;
            goto _cleanUp;
        }
    }
    else {
        info_t("ControlService - Stopped the service");
        bStoppedOrAlreadyStopped = TRUE;
    }

    // Delete the service if it was stopped or already inactive
    if (bStoppedOrAlreadyStopped) {
        // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice
        if (!DeleteService(hService)) {
            errorWin32("DeleteService - Failed to delete service");
            bSTATE = FALSE;
            goto _cleanUp;
        }
        info_t("DeleteService - Deleted the service");
    }

_cleanUp:

    // Close handles to the service and SCM
    if (hService) {
        CloseServiceHandle(hService);
    }
    if (hScm) {
        CloseServiceHandle(hScm);
    }

    return bSTATE;
}


HANDLE GetDeviceHandle(IN LPCWSTR lpwcDriverSymlink) {
    
    HANDLE hDevice = NULL; // Stores handle to the device

    // Open a file handle to the driver using its symbolic link
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
    hDevice = CreateFileW(
        lpwcDriverSymlink,			// Symbolic link to RTCore64 driver
        GENERIC_READ                // Read access
        | GENERIC_WRITE,		    // Write access
        0,							// No sharing
        NULL,						// Default security attributes
        OPEN_EXISTING,				// Open the existing device
        FILE_ATTRIBUTE_NORMAL,		// Normal file attributes
        NULL						// No template file
    );
    if (hDevice == INVALID_HANDLE_VALUE) {
        errorWin32("CreateFileW - Failed to open the device");
        return NULL;
    }
    //info_t("CreateFileW - Opened file handle to driver at 0x%p", hDevice);
    
    // Return the valid device handle
    return hDevice;

}