#pragma once
#include "RPC-Lib/Utils.h"
#include <tlhelp32.h>
#include <Bits.h>
#include <deliveryoptimization.h>
#include "StorSvc_h.h"

using std::stringstream;

#define PROTSEC L"ncalrpc"
wstring g_RemoteServer;
RPC_IF_HANDLE INTERFACES[] = { StorSvc_v0_0_s_ifspec };
const wstring ORIGINAL_RPC_SERVICE = L"StorSvc";
const wstring REGISTER_FLAG = L"/register";
wstring TASK_NAME = L"RPC-Racer";


wstring GetProcFileName(DWORD Pid);
void SidToUsername(PSID Sid, wstring& Username, wstring& SidString);
void LogCallAttributes(RPC_BINDING_HANDLE BindingHandle);
wstring GetImpersonationLevel(HANDLE TokenHandle);
HANDLE GetRpcClientToken(RPC_BINDING_HANDLE BindingHandle);
void GetSidAndUsername(HANDLE ThreadToken, wstring& SidStr, wstring& UsernameStr);
void LogTokenInfo(RPC_BINDING_HANDLE BindingHandle);
void LogConnectionInfo(RPC_BINDING_HANDLE BindingHandle);
RPC_STATUS RpcIfCallbackFn(RPC_IF_HANDLE InterfaceUuid, void* Context);
void RegisterServer(RPC_IF_HANDLE Interface, wchar_t* Protseq, wchar_t* Endpoint, wchar_t* Annotation);
void TriggerCreateJob(LPCWSTR JobName);
void QueryStatusService(const wstring& ServiceName);