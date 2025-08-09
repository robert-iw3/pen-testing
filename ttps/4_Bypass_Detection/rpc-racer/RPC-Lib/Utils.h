#pragma once
#include <Windows.h>
#include <sddl.h>
#include <taskschd.h>
#include <comdef.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <iostream>

using std::endl;
using std::cout;
using std::wcout;
using std::runtime_error;
using std::wstring;
using std::string;

string TranslateCode(DWORD ErrorCode);
void ThrowException(const char* Message, const DWORD ErrorCode);
wstring IfIdToWstring(const RPC_IF_ID* IfID);
wstring UuidToWstring(const UUID* Uuid);
wstring BindHandleToWstring(RPC_BINDING_HANDLE Handle);
wstring GetServiceNameFromPid(DWORD Pid);
void SidToUsername(PSID Sid, wstring& Username, wstring& SidString);
void GetSidAndUsername(HANDLE Token, wstring& SidStr, wstring& UsernameStr);
void RegisterScheduledTask(wstring& TaskName, wstring& Argument, bool HighestPrivileges);