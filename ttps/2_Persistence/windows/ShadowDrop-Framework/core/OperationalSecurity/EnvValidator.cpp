#include "EnvValidator.h"
#include <Windows.h>
#include <winnls.h>

BOOL EnvValidator::IsDebuggerPresent() {
    BOOL result = FALSE;
    __try {
        __asm {
            push eax
            mov eax, fs:[0x30]
            mov al, [eax+2]
            test al, al
            pop eax
        }
        result = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }
    return result;
}

BOOL EnvValidator::IsInsideVM() {
    unsigned int cpuInfo[4];
    __cpuid(reinterpret_cast<int*>(cpuInfo), 1);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

BOOL EnvValidator::IsAuthorizedDomain() {
    WCHAR domain[MAX_PATH];
    DWORD size = MAX_PATH;
    if (!GetComputerNameExW(ComputerNameDnsDomain, domain, &size))
        return FALSE;

    // allowed domains
    const wchar_t* allowed[] = { L"lab1.corp", L"lab2.corp" };
    for (auto& env : allowed) {
        if (wcsstr(domain, env) return TRUE;
    }
    return FALSE;
}

BOOL EnvValidator::IsPermittedGeo() {
    GEOID geoId = GetUserGeoID(GEOCLASS_NATION);
    return geoId != 185 && geoId != 46 && geoId != 156; // block ru,cn,sy
}
