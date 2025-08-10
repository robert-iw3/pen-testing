#include "Utils.h"

SC_HANDLE g_ScHandle = nullptr;

// Get description of error code for more informative logging
string TranslateCode(DWORD ErrorCode)
{
	string errorMessage;
	LPSTR messageBuffer;
	HMODULE source = GetModuleHandleW(L"NTDLL.DLL");

	DWORD bufferLength = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_FROM_HMODULE,
		source,
		ErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPSTR>(&messageBuffer),
		0,
		NULL);

	if (0 != bufferLength)
	{
		errorMessage.assign(messageBuffer);
		LocalFree(messageBuffer);
	}
	return errorMessage;
}

// Add more information to the error message before throwing
void ThrowException(const char* Message, const DWORD ErrorCode)
{
	string codeMeaning = TranslateCode(ErrorCode);
	std::stringstream messageStream;
	messageStream << Message;
	messageStream << " 0x";
	messageStream << std::hex << ErrorCode << std::dec << " " << codeMeaning;
	const string errorMessage = messageStream.str();
	throw runtime_error(errorMessage.c_str());
}

// Convert the interface UUID along with the version number to std::wstring
wstring IfIdToWstring(const RPC_IF_ID* IfID)
{
	RPC_WSTR stringBuffer = nullptr;
	UuidToStringW(&IfID->Uuid, &stringBuffer);
	wstring UuidStr = reinterpret_cast<wchar_t*>(stringBuffer);
	std::transform(UuidStr.begin(), UuidStr.end(), UuidStr.begin(), ::toupper);
	RpcStringFreeW(&stringBuffer);
	wstring majorNum = std::to_wstring(IfID->VersMajor);
	wstring minorNum = std::to_wstring(IfID->VersMinor);
	UuidStr.append(L" ");
	UuidStr.append(majorNum);
	UuidStr.append(L".");
	UuidStr.append(minorNum);
	return UuidStr;
}

// Convert only the interface UUID to std::wstring
wstring UuidToWstring(const UUID* Uuid)
{
	RPC_WSTR stringBuffer = nullptr;
	UuidToStringW(Uuid, &stringBuffer);
	wstring UuidStr = reinterpret_cast<wchar_t*>(stringBuffer);
	RpcStringFreeW(&stringBuffer);
	return UuidStr;
}

wstring BindHandleToWstring(RPC_BINDING_HANDLE Handle)
{
	RPC_WSTR stringBuffer = nullptr;
	RpcBindingToStringBindingW(Handle, &stringBuffer);
	wstring bindString = reinterpret_cast<wchar_t*>(stringBuffer);
	RpcStringFreeW(&stringBuffer);
	return bindString;
}

// Open a handle to the service manager only once for more efficient code
void SetGlobalServiceHandle()
{
	SC_HANDLE scHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (nullptr == scHandle)
		ThrowException("OpenSCManager failed", GetLastError());

	g_ScHandle = scHandle;
}

// Enumerate all the services to find the one that matches the requested PID
wstring GetServiceNameFromPid(DWORD Pid)
{
	if (nullptr == g_ScHandle)
		SetGlobalServiceHandle();

	wstring serviceName = L"N/A";
	DWORD bytesNeeded = 0;
	DWORD servicesCount = 0;
	DWORD resumeHandle = 0;

	// Retrieve the requeired buffer size
	BOOL success = EnumServicesStatusExW(g_ScHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, nullptr, 0, &bytesNeeded, &servicesCount, &resumeHandle, nullptr);
	while (!success)
	{
		// Allocate the buffer
		PBYTE servicesBuffer = new BYTE[bytesNeeded];

		// Request the data again
		success = EnumServicesStatusExW(g_ScHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, servicesBuffer, bytesNeeded, &bytesNeeded, &servicesCount, &resumeHandle, nullptr);
		LPENUM_SERVICE_STATUS_PROCESSW servicesArray = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(servicesBuffer);
		for (DWORD i = 0; i < servicesCount; i++)
		{
			LPENUM_SERVICE_STATUS_PROCESSW currentService = &servicesArray[i];
			if (currentService->ServiceStatusProcess.dwProcessId == Pid)
			{
				serviceName = currentService->lpDisplayName;
				delete[] servicesBuffer;
				return serviceName;
			}
		}
		delete[] servicesBuffer;
	}
	return serviceName;
}

// Translate security identifier
void SidToUsername(PSID Sid, wstring& Username, wstring& SidString)
{
	if (!IsValidSid(Sid))
	{
		wcout << L"SID is invalid" << endl;
		return;
	}

	DWORD usernameLength = 0;
	DWORD domainLength = 0;
	SID_NAME_USE sidType;

	// Retrieve the requeired buffer size
	BOOL success = LookupAccountSidW(nullptr, Sid, nullptr, &usernameLength, nullptr, &domainLength, &sidType);
	DWORD error = GetLastError();
	if (!success && ERROR_INSUFFICIENT_BUFFER != error)
	{
		wcout << L"retrieving username allocation size failed " << error << endl;
		return;
	}

	// Allocate the buffer
	wchar_t* usernameBuffer = new wchar_t[usernameLength];
	wchar_t* domainBuffer = new wchar_t[domainLength];

	// Request the data again
	success = LookupAccountSidW(nullptr, Sid, usernameBuffer, &usernameLength, domainBuffer, &domainLength, &sidType);
	if (!success)
	{
		wcout << L"retrieving username failed " << GetLastError() << endl;
		delete[] usernameBuffer;
		delete[] domainBuffer;
		return;
	}

	Username.assign(domainBuffer);
	Username.append(L"\\");
	Username.append(usernameBuffer);
	delete[] usernameBuffer;
	delete[] domainBuffer;

	LPWSTR sidStringBuffer = nullptr;

	// Convert security identifier from binary data to string
	success = ConvertSidToStringSidW(Sid, &sidStringBuffer);
	if (!success)
	{
		wcout << L"ConvertSidToStringSidW failed " << GetLastError() << endl;
		return;
	}
	SidString.assign(sidStringBuffer);
	LocalFree(sidStringBuffer);
}

void GetSidAndUsername(HANDLE Token, wstring& SidStr, wstring& UsernameStr)
{
	DWORD bytesNeeded = 0;
	GetTokenInformation(Token, TokenUser, nullptr, 0, &bytesNeeded);
	PBYTE tokenUserBuffer = new BYTE[bytesNeeded];
	if (!GetTokenInformation(Token, TokenUser, tokenUserBuffer, bytesNeeded, &bytesNeeded))
	{
		wcout << "GetTokenInformation for TokenUser failed " << GetLastError() << endl;
		return;
	}
	PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(tokenUserBuffer);
	SidToUsername(tokenUser->User.Sid, UsernameStr, SidStr);
	delete[] tokenUserBuffer;
}

void RegisterScheduledTask(wstring& TaskName, wstring& Argument, bool HighestPrivileges)
{
	HRESULT hr = S_OK;
	hr = CoInitialize(nullptr);
	if (FAILED(hr))
		ThrowException("CoInitialize failed", hr);

	hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, 0, nullptr);
	if (FAILED(hr))
		ThrowException("CoInitializeSecurity failed", hr);

	ITaskService* taskService = nullptr;
	hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, reinterpret_cast<PVOID*>(&taskService));
	if (FAILED(hr))
	{
		CoUninitialize();
		ThrowException("CoCreateInstance for IID_ITaskService failed", hr);
	}

	hr = taskService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
	if (FAILED(hr))
	{
		taskService->Release();
		CoUninitialize();
		ThrowException("ITaskService::Connect failed", hr);
	}

	ITaskFolder* taskFolder = nullptr;
	wchar_t folderPath[] = L"\\";
	hr = taskService->GetFolder(folderPath, &taskFolder);
	if (FAILED(hr))
	{
		taskService->Release();
		CoUninitialize();
		ThrowException("ITaskService::GetFolder failed", hr);
	}

	ITaskDefinition* taskDefinition = nullptr;
	hr = taskService->NewTask(0, &taskDefinition);
	taskService->Release();
	if (FAILED(hr))
	{
		taskFolder->Release();
		CoUninitialize();
		ThrowException("ITaskService::NewTask failed", hr);
	}

	if (HighestPrivileges)
	{
		IPrincipal* principal = nullptr;
		hr = taskDefinition->get_Principal(&principal);
		if (FAILED(hr))
		{
			taskFolder->Release();
			taskDefinition->Release();
			CoUninitialize();
			ThrowException("ITaskDefinition::get_Principal failed", hr);
		}
		hr = principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
		principal->Release();
		if (FAILED(hr))
		{
			taskFolder->Release();
			taskDefinition->Release();
			CoUninitialize();
			ThrowException("ITaskDefinition::get_Principal failed", hr);
		}
	}

	ITriggerCollection* triggerCollection = nullptr;
	hr = taskDefinition->get_Triggers(&triggerCollection);
	if (FAILED(hr))
	{
		taskFolder->Release();
		taskDefinition->Release();
		CoUninitialize();
		ThrowException("ITaskDefinition::get_Triggers failed", hr);
	}

	ITrigger* trigger = nullptr;
	hr = triggerCollection->Create(TASK_TRIGGER_LOGON, &trigger);
	triggerCollection->Release();
	if (FAILED(hr))
	{
		taskFolder->Release();
		taskDefinition->Release();
		CoUninitialize();
		ThrowException("ITriggerCollection::Create failed", hr);
	}

	ILogonTrigger* logonTrigger = nullptr;
	hr = trigger->QueryInterface(IID_ILogonTrigger, reinterpret_cast<PVOID*>(&logonTrigger));
	trigger->Release();
	if (FAILED(hr))
	{
		taskFolder->Release();
		taskDefinition->Release();
		CoUninitialize();
		ThrowException("ITrigger::QueryInterface failed", hr);
	}

	HANDLE tokenHandle = GetCurrentProcessToken();
	wstring sidStr;
	wstring usernameStr;
	GetSidAndUsername(tokenHandle, sidStr, usernameStr);
	CloseHandle(tokenHandle);
	hr = logonTrigger->put_UserId(usernameStr.data());
	logonTrigger->Release();
	if (FAILED(hr))
	{
		taskFolder->Release();
		taskDefinition->Release();
		CoUninitialize();
		ThrowException("ILogonTrigger::put_UserId failed", hr);
	}

	IActionCollection* actionCollection = nullptr;
	hr = taskDefinition->get_Actions(&actionCollection);
	if (FAILED(hr))
	{
		taskFolder->Release();
		taskDefinition->Release();
		CoUninitialize();
		ThrowException("ITaskDefinition::get_Actions failed", hr);
	}

	IAction* action = nullptr;
	hr = actionCollection->Create(TASK_ACTION_EXEC, &action);
	actionCollection->Release();
	if (FAILED(hr))
	{
		taskFolder->Release();
		taskDefinition->Release();
		CoUninitialize();
		ThrowException("IActionCollection::Create failed", hr);
	}

	IExecAction* execAction = nullptr;
	hr = action->QueryInterface(IID_IExecAction, reinterpret_cast<PVOID*>(&execAction));
	action->Release();
	if (FAILED(hr))
	{
		taskFolder->Release();
		taskDefinition->Release();
		CoUninitialize();
		ThrowException("IAction::QueryInterface failed", hr);
	}

	wchar_t path[MAX_PATH] = {};
	GetModuleFileNameW(GetModuleHandleW(nullptr), path, MAX_PATH);
	hr = execAction->put_Path(path);
	if (FAILED(hr))
	{
		execAction->Release();
		taskFolder->Release();
		taskDefinition->Release();
		CoUninitialize();
		ThrowException("IExecAction::put_Path failed", hr);
	}

	if (!Argument.empty())
	{
		hr = execAction->put_Arguments(Argument.data());
		if (FAILED(hr))
		{
			execAction->Release();
			taskFolder->Release();
			taskDefinition->Release();
			CoUninitialize();
			ThrowException("IExecAction::put_Arguments failed", hr);
		}
	}
	execAction->Release();

	IRegisteredTask* registeredTask = nullptr;
	hr = taskFolder->RegisterTaskDefinition(TaskName.data(), taskDefinition, TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""), &registeredTask);
	taskFolder->Release();
	taskDefinition->Release();
	if (FAILED(hr))
	{
		CoUninitialize();
		ThrowException("ITaskFolder::RegisterTaskDefinition failed", hr);
	}
	registeredTask->Release();
	CoUninitialize();
	wcout << L"Task created" << endl;
}