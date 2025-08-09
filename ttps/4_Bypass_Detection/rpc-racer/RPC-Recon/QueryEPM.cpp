#include "QueryEPM.h"
#include "GuidMaps.h"

// Store all the interfaces registered to the Endpoint Mapper as keys and the endpoints that expose them as values
void QueryEpm(map<wstring, vector<wstring>>& IfMap)
{
	// Get inquiry context from the Endpoint Mapper
	RPC_EP_INQ_HANDLE inqHandle = nullptr;
	RPC_STATUS status = RpcMgmtEpEltInqBegin(nullptr, RPC_C_EP_ALL_ELTS, nullptr, 0, nullptr, &inqHandle);
	if (RPC_S_OK != status)
		ThrowException("RpcMgmtEpEltInqBegin failed", status);

	while (true)
	{
		RPC_IF_ID ifId = {};
		RPC_BINDING_HANDLE serverBindingHandle = nullptr;
		UUID objectUuid = {};
		RPC_WSTR annotation = nullptr;

		// Enumerate all entries
		status = RpcMgmtEpEltInqNextW(inqHandle, &ifId, &serverBindingHandle, &objectUuid, &annotation);
		if (RPC_X_NO_MORE_ENTRIES == status)
			break;
		if (RPC_S_OK != status)
			ThrowException("RpcMgmtEpEltInqNextW failed", status);

		// Convert variables to std::wstring
		wstring ifUuidStr = IfIdToWstring(&ifId);
		ifUuidStr.append(L" ");
		ifUuidStr.append(reinterpret_cast<wchar_t*>(annotation));
		wstring serverBindString = BindHandleToWstring(serverBindingHandle);
		RpcBindingFree(&serverBindingHandle);
		RpcStringFreeW(&annotation);

		// Check if the interface was alreay stored in the map
		map<wstring, vector<wstring>>::iterator it = IfMap.find(ifUuidStr);
		if (it == IfMap.end())
		{
			// If not, add a new pair
			vector<wstring> bindingsVector = { serverBindString };
			IfMap.insert({ ifUuidStr, bindingsVector });
		}
		else
		{
			// If yes, add to existing vector
			it->second.push_back(serverBindString);
		}
	}
	RpcMgmtEpEltInqDone(&inqHandle);
}

void CompareEpmResults(map<wstring, vector<wstring>>& EpmEarly, map<wstring, vector<wstring>>& EpmLate, wstringstream& OutStream)
{
	for (auto const& [uuid, bindingVector] : EpmLate)
	{
		// skip interfaces that were registered by the first scan
		if (EpmEarly.find(uuid) != EpmEarly.end())
			continue;

		// Correlate between UUIDs and known RPC servers
		wstring protocol = L"N/A";
		for (const auto& [key, value] : KNOWN_PROTOCOLS)
		{
			if (uuid.rfind(key) == 0)
			{
				protocol = value;
				break;
			}
		}
		wstring provider = L"N/A";
		for (const auto& [key, value] : KNOWN_UUIDS)
		{
			if (uuid.rfind(key) == 0)
			{
				provider = value;
				break;
			}
		}

		// Add the results to the output stream
		OutStream << L"Protocol: " << protocol << endl;
		OutStream << L"Provider: " << provider << endl;
		OutStream << L"UUID    : " << uuid << endl;
		OutStream << L"Bindings: " << endl;
		for (auto const& bindString : bindingVector)
			OutStream << L"          " << bindString << endl;
		OutStream << L"--------------------------------------------" << endl;
	}
}