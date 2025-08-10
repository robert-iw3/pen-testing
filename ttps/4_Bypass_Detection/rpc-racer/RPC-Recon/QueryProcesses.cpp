#include "QueryProcesses.h"

PBYTE g_Rpcrt4DataSectionStart = 0;
DWORD g_Rpcrt4DataSectionSize = 0;

RPC_SYNTAX_IDENTIFIER DceRpcSyntaxUuid =
{
	{ 0x8a885d04,0x1ceb,0x11c9,{ 0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60 } },
	{ 2,0 }
};

void EnablePrivilege(const HANDLE TokenHandle, const LPCWSTR Privilege)
{
	TOKEN_PRIVILEGES tokenPrivileges = {};

	if (!::LookupPrivilegeValueW(nullptr, Privilege, &tokenPrivileges.Privileges[0].Luid))
	{
		CloseHandle(TokenHandle);
		ThrowException("[EnablePrivilege] LookupPrivilegeValueW failed", GetLastError());
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!::AdjustTokenPrivileges(TokenHandle, 0, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		CloseHandle(TokenHandle);
		ThrowException("[EnablePrivilege] AdjustTokenPrivileges failed", GetLastError());
	}
}

void EnablePrivilegeCurrentProcess(const LPCWSTR Privilege)
{
	HANDLE tokenHandle;
	if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
	{
		EnablePrivilege(tokenHandle, Privilege);
		CloseHandle(tokenHandle);
	}
	else
		ThrowException("[EnablePrivilegeCurrentProcess] OpenProcessToken failed", GetLastError());
}

void EnableDebugPrivilegeCurrentProcess()
{
	EnablePrivilegeCurrentProcess(SE_DEBUG_NAME);
}

bool ReadMemory(HANDLE ProcessHandle, PVOID Source, PVOID Dest, DWORD Size)
{
	SIZE_T bytesRead = 0;
	BOOL success = ReadProcessMemory(ProcessHandle, Source, Dest, Size, &bytesRead);
	return success == TRUE && bytesRead == Size;
}

bool ValidateRpcInterface(HANDLE ProcessHandle, RPC_INTERFACE_T** interfacePtrs, UINT count)
{
	RPC_INTERFACE_T iface = {};

	// Iterate through interfaces
	for (UINT i = 0; i < count; i++) {

		if (ReadMemory(ProcessHandle, interfacePtrs[i], &iface, sizeof(RPC_INTERFACE_T)))
		{
			DWORD reqSize = sizeof(RPC_SERVER_INTERFACE_T);

			// Sanity check for the RPC_INTERFACE struct to look for a known transfer syntax GUID
			if (iface.RpcServerInterface.Length == reqSize &&
				!memcmp(&DceRpcSyntaxUuid, &iface.RpcServerInterface.TransferSyntax, sizeof(DceRpcSyntaxUuid))
				)
				return true;
		}
	}

	return false;
}

RPC_SERVER_T* FindGlobalRpcServer(HANDLE Handle)
{
	DWORD s = sizeof(RPC_SERVER_T);
	RPC_SERVER_T* rpcServer = new RPC_SERVER_T;
	PBYTE searchStartAddr = g_Rpcrt4DataSectionStart;

	// Iterate through .data section to find the RPC_SERVER struct
	for (DWORD i = 0x10e0; i < g_Rpcrt4DataSectionSize; i += 8)
	{
		// Read a potential pointer to RPC_SERVER
		ULONG_PTR pointer = 0;
		if (!ReadMemory(Handle, searchStartAddr + i, &pointer, sizeof(pointer)))
			continue;

		// Attempt to read a potential RPC_SERVER object
		if (!ReadMemory(Handle, reinterpret_cast<PVOID>(pointer), rpcServer, sizeof(RPC_SERVER_T)))
			continue;

		// Sanity check the interface dictionary
		if (0 < rpcServer->InterfaceDict.NumberOfEntries && rpcServer->InterfaceDict.NumberOfEntries <= MAX_SIMPLE_DICT_ENTRIES)
		{
			DWORD interfaceDictSize = rpcServer->InterfaceDict.NumberOfEntries * sizeof(PVOID);
			PBYTE interfaceDictBuffer = new BYTE[interfaceDictSize];
			if (!ReadMemory(Handle, rpcServer->InterfaceDict.pArray, interfaceDictBuffer, interfaceDictSize))
			{
				delete[] interfaceDictBuffer;
				continue;
			}

			// Pass to validation function for further checks
			if (ValidateRpcInterface(Handle, reinterpret_cast<RPC_INTERFACE_T**>(interfaceDictBuffer), rpcServer->InterfaceDict.NumberOfEntries))
			{
				rpcServer->InterfaceDict.pArray = reinterpret_cast<PVOID*>(interfaceDictBuffer);
				return rpcServer;
			}
			delete[] interfaceDictBuffer;
		}
	}
	delete rpcServer;
	return nullptr;
}

void ExtractEndpointsInProcess(HANDLE Handle, RPC_SERVER_T* RpcServer, vector<wstring>& Endpoints)
{
	if (0 == RpcServer->AddressDict.NumberOfEntries || RpcServer->AddressDict.NumberOfEntries > MAX_SIMPLE_DICT_ENTRIES)
		return;

	DWORD addressDictSize = RpcServer->AddressDict.NumberOfEntries * sizeof(PVOID);
	PVOID* addressDictBuffer = reinterpret_cast<PVOID*>(new BYTE[addressDictSize]);
	if (!ReadMemory(Handle, RpcServer->AddressDict.pArray, addressDictBuffer, addressDictSize))
	{
		delete[] addressDictBuffer;
		return;
	}

	for (UINT i = 0; i < RpcServer->AddressDict.NumberOfEntries; i++)
	{
		RPC_ADDRESS_T rpcAddress = {};
		WCHAR ProtocoleW[RPC_MAX_ENDPOINT_PROTOCOL_SIZE] = {};
		WCHAR NameW[RPC_MAX_ENDPOINT_NAME_SIZE] = {};
		if (!ReadMemory(Handle, addressDictBuffer[i], &rpcAddress, sizeof(rpcAddress)))
			break;

		if (!ReadMemory(Handle, rpcAddress.Protocole, ProtocoleW, sizeof(ProtocoleW)))
			break;

		if (!ReadMemory(Handle, rpcAddress.Name, NameW, sizeof(NameW)))
			break;

		wstring endpoint = ProtocoleW;
		if (!endpoint.compare(L"ncacn_np"))
		{
			endpoint.append(L":[\\\\");
			endpoint.append(&NameW[1], 4);
			endpoint.append(L"\\\\");
			endpoint.append(&NameW[6]);
		}
		else
		{
			endpoint.append(L":[");
			endpoint.append(NameW);
		}
		endpoint.append(L"]");

		// Exclude interface registered by combase.dll in every process
		if (!endpoint.starts_with(L"ncalrpc:[OLE"))
		{
			Endpoints.push_back(endpoint);
		}

	}

	delete[] addressDictBuffer;
}

bool IsComInterface(wstring& Uuid)
{
	wstring keyName = L"Interface\\";
	keyName.append(Uuid);
	HKEY hKey = nullptr;
	LSTATUS status = RegOpenKeyExW(HKEY_CLASSES_ROOT, keyName.c_str(), 0, KEY_READ, &hKey);
	if (status == ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return true;
	}
	// Exclude interface registered by combase.dll in every process
	return !Uuid.compare(L"18f70770-8e64-11cf-9af1-0020af6e72f4");
}

bool IsRpcInterface(RPC_INTERFACE_T* RpcIf)
{
	if (RpcIf->Flags & RPC_IF_OLE)
		return false;

	wstring uuid = UuidToWstring(&RpcIf->RpcServerInterface.InterfaceId.Uuid);
	return !IsComInterface(uuid);
}

void ExtractInterfacesInProcess(HANDLE Handle, RPC_SERVER_T* RpcServer, vector<wstring>& Interfaces)
{
	for (UINT i = 0; i < RpcServer->InterfaceDict.NumberOfEntries; i++)
	{
		PVOID interfaceAddress = RpcServer->InterfaceDict.pArray[i];
		RPC_INTERFACE_T iface = {};
		if (!ReadMemory(Handle, interfaceAddress, &iface, sizeof(iface)))
			return;

		if (IsRpcInterface(&iface))
		{
			wstring guid = IfIdToWstring(&iface.RpcServerInterface.InterfaceId);
			Interfaces.push_back(guid);
		}
	}
}

void ExtractDataFromProcess(DWORD Pid, wstring& Name, HANDLE Handle, map<DWORD, map<wstring, vector<wstring>>>& RpcServers)
{
	RPC_SERVER_T* rpcServer = FindGlobalRpcServer(Handle);
	if (nullptr == rpcServer)
		return;

	vector<wstring> endpoints;
	vector<wstring> interfaces;
	ExtractEndpointsInProcess(Handle, rpcServer, endpoints);
	ExtractInterfacesInProcess(Handle, rpcServer, interfaces);

	// Skip processes that aren't RPC servers
	if (endpoints.size() > 0 || interfaces.size() > 0)
	{
		wstring serviceName = GetServiceNameFromPid(Pid);
		map<wstring, vector<wstring>> serverData;
		serverData[L"Process Name"] = { Name };
		serverData[L"Service Name"] = { serviceName };
		serverData[L"Endpoints"] = endpoints;
		serverData[L"UUIDs"] = interfaces;
		RpcServers[Pid] = serverData;
	}

	delete[] rpcServer->InterfaceDict.pArray;
	delete rpcServer;
}

// The offset of the .data section inside rpcrt4.dll will be the same for every process
// Find it only once to increase efficiency
void SetRpcrt4DataVA()
{
	HMODULE moduleHandle = GetModuleHandle(L"rpcrt4.dll");
	PBYTE baseAddress = reinterpret_cast<PBYTE>(moduleHandle);
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);
	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(baseAddress + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER currentSection = &sectionHeader[i];
		if (!strcmp(reinterpret_cast<const char*>(currentSection->Name), ".data"))
		{
			g_Rpcrt4DataSectionStart = baseAddress + currentSection->VirtualAddress;
			g_Rpcrt4DataSectionSize = currentSection->Misc.VirtualSize;
			return;
		}
	}
	ThrowException(".data section not found for rpcrt4.dll", ERROR_NOT_FOUND);
}

bool IsProcessValidTarget(DWORD Pid, wstring& Name, PHANDLE Handle)
{
	// Protected Process Light denies PROCESS_VM_READ
	HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, Pid);
	if (nullptr == processHandle)
	{
		wcout << L"cannot open handle for " << Name << L" pid " << Pid << endl;
		wcout << L"--------------------------------------------" << endl;
		return false;
	}
	BOOL isWow = FALSE;
	BOOL success = IsWow64Process(processHandle, &isWow);
	if (!success)
	{
		wcout << L"IsWow64Process failed for process " << Name << L" pid " << Pid << endl;
		wcout << L"--------------------------------------------" << endl;
		CloseHandle(processHandle);
		return false;
	}
	if (isWow)
	{
		wcout << L"skipping wow64 process " << Name << L" pid " << Pid << endl;
		wcout << L"--------------------------------------------" << endl;
		CloseHandle(processHandle);
		return false;
	}
	*Handle = processHandle;
	return true;
}

/*
map exmaple:
{
	1000:
	{
		"process name": ["svchost.exe"],
		"service name": ["Storage Service"],
		"Endpoints": 	["ncalrpc:[LRPC-f5cbd0ccb243772b5c]"],
		"UUIDs": 		["44D1520B-6133-41F0-8A66-D37305ECC357 0.0", "28942101-43DF-4EB7-B1DD-2C0C0EBF99C0 0.0"]
	}
}
*/
void QueryProcesses(map<DWORD, map<wstring, vector<wstring>>>& RpcServers)
{
	// Debug privileges are required to read the memory of elevated processes
	EnableDebugPrivilegeCurrentProcess();
	SetRpcrt4DataVA();
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == snapshotHandle)
		ThrowException("CreateToolhelp32Snapshot failed", GetLastError());

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(PROCESSENTRY32W);
	if (!Process32FirstW(snapshotHandle, &entry))
	{
		CloseHandle(snapshotHandle);
		ThrowException("CreateToolhelp32Snapshot failed", GetLastError());
	}

	do
	{
		wstring processName = entry.szExeFile;
		DWORD pid = entry.th32ProcessID;
		HANDLE processHandle = nullptr;

		if (!IsProcessValidTarget(pid, processName, &processHandle))
			continue;
		ExtractDataFromProcess(pid, processName, processHandle, RpcServers);
		CloseHandle(processHandle);
	} while (Process32NextW(snapshotHandle, &entry));
	CloseHandle(snapshotHandle);
}

void CompareProcsResults(map<DWORD, map<wstring, vector<wstring>>>& ProcsEarly, map<DWORD, map<wstring, vector<wstring>>>& ProcsLate, wstringstream& OutStream)
{
	for (auto const& [pid, lateServerData] : ProcsLate)
	{
		auto const& serverDataIter = ProcsEarly.find(pid);

		// The process was created late. Display all the data
		if (serverDataIter == ProcsEarly.end())
		{
			OutStream << L"PID: " << pid << endl;
			OutStream << L"Process Name: " << lateServerData.at(L"Process Name").at(0) << endl;
			OutStream << L"Service Name: " << lateServerData.at(L"Service Name").at(0) << endl;
			OutStream << L"Endpoints: " << endl;
			for (auto const& endpoint : lateServerData.at(L"Endpoints"))
				OutStream << L"          " << endpoint << endl;
			OutStream << L"UUIDs: " << endl;
			for (auto const& uuid : lateServerData.at(L"UUIDs"))
				OutStream << L"          " << uuid << endl;
			OutStream << L"--------------------------------------------" << endl;
		}
		// The process was created early. Check if the endpoints and interfaces were created late
		else
		{
			auto const& earlyServerData = (*serverDataIter).second;
			auto const& earlyEndpoints = earlyServerData.at(L"Endpoints");
			auto const& lateEndpoints = lateServerData.at(L"Endpoints");
			auto const& earlyUuids = earlyServerData.at(L"UUIDs");
			auto const& lateUuids = lateServerData.at(L"UUIDs");
			if (lateEndpoints.size() > earlyEndpoints.size() || lateUuids.size() > earlyUuids.size())
			{
				OutStream << L"PID: " << pid << endl;
				OutStream << L"Process Name: " << lateServerData.at(L"Process Name").at(0) << endl;
				OutStream << L"Service Name: " << lateServerData.at(L"Service Name").at(0) << endl;
				OutStream << L"Endpoints: " << endl;
				for (auto const& lateEndpoint : lateEndpoints)
				{
					bool endpointRegisteredEarly = false;
					for (auto const& earlyEndpoint : earlyEndpoints)
					{
						if (!lateEndpoint.compare(earlyEndpoint))
							endpointRegisteredEarly = true;
					}
					if (!endpointRegisteredEarly)
						OutStream << L"          " << lateEndpoint << endl;
				}

				OutStream << L"UUIDs: " << endl;
				for (auto const& lateUuid : lateUuids)
				{
					bool uuidRegisteredEarly = false;
					for (auto const& earlyUuid : earlyUuids)
					{
						if (!lateUuid.compare(earlyUuid))
							uuidRegisteredEarly = true;
					}
					if (!uuidRegisteredEarly)
						OutStream << L"          " << lateUuid << endl;
				}
				OutStream << L"--------------------------------------------" << endl;
			}
		}
	}
}