#include "common.h"

// Print help functionality
VOID PrintHelp(IN CHAR* _Argv0) {

	error("Usage: %s <PAYLOAD FILE>", _Argv0);

	return EXIT_FAILURE;

}

// Print the input buffer as a hex char array (c syntax)
VOID PrintHexData(IN LPCSTR Name, IN PBYTE Data, IN SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n");

}

int main(int argc, char* argv[]) {

	DWORD	dwPayloadSize	= NULL; // Size of the payload
	PBYTE	pbPayload		= NULL; // Pointer to payload

	// Checking input
	if (argc != 2) {
		PrintHelp(argv[0]);
		return EXIT_FAILURE;
	}

	// Read payload
	info("ReadPayloadFile - Reading payload");
	if (!ReadPayloadFile(argv[1], &dwPayloadSize, &pbPayload)) {
		error("ReadPayloadFile - Failed to read file");
		return FALSE;
	}
	info("ReadPayloadFile - Read %d payload bytes", dwPayloadSize);

	PrintHexData("cDriver", pbPayload, dwPayloadSize);
	printf("unsigned int cDriverLength = sizeof(cDriver);");

	return EXIT_SUCCESS;
}
