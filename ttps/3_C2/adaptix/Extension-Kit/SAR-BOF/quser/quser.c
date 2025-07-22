#include <windows.h>
#include <wtsapi32.h>
#include "base.c"

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI WTSAPI32$WTSOpenServerA (LPSTR);
DECLSPEC_IMPORT WINBASEAPI void WINAPI WTSAPI32$WTSCloseServer (HANDLE);




void PrintLogonTime(LARGE_INTEGER logonTime)
{
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    fileTime.dwLowDateTime = logonTime.LowPart;
    fileTime.dwHighDateTime = logonTime.HighPart;

    if (KERNEL32$FileTimeToSystemTime(&fileTime, &systemTime)) {
        internal_printf("%02d/%02d/%d %02d:%02d:%02d\n",
               systemTime.wMonth, systemTime.wDay, systemTime.wYear,
               systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
    } else {
        internal_printf("Failed to convert LogonTime to SystemTime\n");
    }
}

void go(char * args, int alen)
{	
    if(!bofstart()){
        return;
    }
	datap parser;
	PWTS_SESSION_INFOA pwsi;
	DWORD dwCount = 0;
	DWORD bytesReturned = 0;
	BeaconDataParse(&parser, args, alen);
	char *targetHost = BeaconDataExtract(&parser, NULL);
	char *addrFamily = "";
	char *stateInfo = "";
	HANDLE hTarget = NULL;
	LPTSTR userName, userDomain, clientName, clientAddress, sessionInfo;
	PWTS_CLIENT_ADDRESS clientAddressStruct = NULL;
	BOOL successGetSession = 0;
	hTarget = WTSAPI32$WTSOpenServerA(targetHost);
	successGetSession = WTSAPI32$WTSEnumerateSessionsA(hTarget, 0, 1, &pwsi, &dwCount);
	if(!successGetSession){
		if(KERNEL32$GetLastError()==5)
			BeaconPrintf(CALLBACK_OUTPUT, "Access denied: Could not connect to %s.", targetHost);
		else
			BeaconPrintf(CALLBACK_OUTPUT, "ERROR %d: Could not connect to %s.", KERNEL32$GetLastError(), targetHost);
	} else {
		internal_printf("%-20s%-25s%-15s%-15s%-15s%-18s%-25s%s\n", "UserDomain", "UserName", "SessionName", "SessionID" , "State", "SourceAddress", "SourceClientName", "LogonTime");
		for (unsigned int i = 0; i < dwCount; i++)
		{
			WTS_SESSION_INFO si = pwsi[i];
			if(si.SessionId > 2048 || si.SessionId < 0)
				continue;
			BOOL getResult;
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSUserName, &userName, &bytesReturned);
			if(!getResult){
				userName = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSDomainName, &userDomain, &bytesReturned);
			if(!getResult){
				userDomain = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSClientName, &clientName, &bytesReturned);
			if(!getResult){
				clientName = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSClientAddress, &clientAddress, &bytesReturned);
			if(!getResult){
				clientAddress = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			WTSINFO* wtsInfo = NULL;
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSLogonTime, &sessionInfo, &bytesReturned);
			if (getResult && bytesReturned == sizeof(LARGE_INTEGER)) {
				//Second scenario
				WTSAPI32$WTSFreeMemory(sessionInfo);
			}
			else {
				getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSSessionInfo, &sessionInfo, &bytesReturned);
				if (getResult) {
					wtsInfo = (WTSINFO*)sessionInfo;					
					WTSAPI32$WTSFreeMemory(sessionInfo);
				}
			}
			clientAddressStruct = (PWTS_CLIENT_ADDRESS)clientAddress;
			if(clientAddressStruct->AddressFamily == 0)
				addrFamily = "Unspecified";
			else if(clientAddressStruct->AddressFamily == 2)
				addrFamily = "InterNetwork";
			else if(clientAddressStruct->AddressFamily == 17)
				addrFamily = "NetBios";
			else 
				addrFamily = "Unknown";
			if(strlen(userName)){
				if(si.State == WTSActive)
					stateInfo = "Active";
				else if(si.State == WTSConnected)
					stateInfo = "Connected";
				else if(si.State == WTSDisconnected)
					stateInfo = "Disconnected";
				else if(si.State == WTSIdle)
					stateInfo = "Idle";
				else 
					stateInfo = "Unknown";
				if(addrFamily == "Unspecified"){
                    internal_printf("%-20s%-25s%-15s%-15i%-15s%-18s%-25s", userDomain, userName, si.pWinStationName, si.SessionId, stateInfo, "-", "-");
					PrintLogonTime(wtsInfo->LogonTime);
				}
                else{
                    internal_printf("%-20s%-25s%-15s%-15i%-15s%u.%u.%u.%-10u%-25s", userDomain, userName, si.pWinStationName, si.SessionId, stateInfo, clientAddressStruct->Address[2], clientAddressStruct->Address[3], clientAddressStruct->Address[4], clientAddressStruct->Address[5], clientName);
					PrintLogonTime(wtsInfo->LogonTime);
				}
			}
		}
	}
    printoutput(TRUE);
	WTSAPI32$WTSFreeMemory(pwsi);
	WTSAPI32$WTSCloseServer(hTarget);
    bofstop();
};