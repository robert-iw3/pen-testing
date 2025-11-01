#include "Finder.h"
#include "Errors.h"
#include "Logger.h"

std::wstring Finder::GetModuleNameFromPid(DWORD pid) {

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

	if (hProcess == NULL) {
		return L"";
	}

	HMODULE hMods[1024];
	DWORD cbNeeded;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		wchar_t moduleName[MAX_PATH];
		if (GetModuleFileNameEx(hProcess, hMods[0], moduleName, sizeof(moduleName) / sizeof(wchar_t))) {
			CloseHandle(hProcess);
			return std::wstring(moduleName);
		}
	}

	CloseHandle(hProcess);
	return L"";
}

DWORD Finder::GetPIDByUIAutomationElement(IUIAutomationElement* pAutomationElement)
{
	VARIANT vPid;
	VariantInit(&vPid);
	HRESULT hr = pAutomationElement->GetCurrentPropertyValue(UIA_ProcessIdPropertyId, &vPid);
	if (FAILED(hr))
	{
		Log(L"pChildEl->GetCurrentPropertyValue(PID) failed", DBG);
	}

	if (V_VT(&vPid) == VT_I4)
	{
		VariantClear(&vPid);
		return V_I4(&vPid);
	}

	VariantClear(&vPid);

	return -1;
}

ULONG Finder::DisplayActiveWindows()
{
	HRESULT hr;
	int length = 0;

	CComPtr<IUIAutomation> pAutomation;
	CComPtr<IUIAutomationElement> pTargetElement;
	CComPtr<IUIAutomationElementArray> pElementsArray;
	CComPtr<IUIAutomationCondition> pCondition;

	hr = CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&pAutomation);
	if (FAILED(hr))
	{
		Log(L"CoCreateInstance() failed", WARNING);
		PrintErrorFromHRESULT(hr);
		return 1;
	}
	Log(L"IUIAutomation creating success", DBG);

	hr = pAutomation->GetRootElement(&pTargetElement);
	if (FAILED(hr))
	{
		Log(L"pAutomation->GetRootElement() failed", WARNING);
		PrintErrorFromHRESULT(hr);
		return 1;
	}
	Log(L"IUIAutomation->GetRootElement() creating success", DBG);

	hr = pAutomation->CreateTrueCondition(&pCondition);
	if (FAILED(hr))
	{
		Log(L"pAutomation->CreateTrueCondition() failed", WARNING);
		PrintErrorFromHRESULT(hr);
		return 1;
	}
	Log(L"IUIAutomation->CreateTrueCondition() success", DBG);

	hr = pTargetElement->FindAll(TreeScope_Children, pCondition, &pElementsArray);
	if (FAILED(hr))
	{
		Log(L"pAutomation->FindAll() failed", WARNING);
		PrintErrorFromHRESULT(hr);
		return 1;
	}


	pElementsArray->get_Length(&length);
	Log(L"Found active windows: " + std::to_wstring(length), INFO);

	for (int i = 0; i < length; i++)
	{
		CComPtr<IUIAutomationElement> pChildEl;
		hr = pElementsArray->GetElement(i, &pChildEl);

		if (FAILED(hr))
		{
			Log(L"pElementsArray->GetElement() failed", DBG);
			continue;
		}

		BSTR bWindowName;
		hr = pChildEl->get_CurrentName(&bWindowName);
		if (FAILED(hr))
		{
			Log(L"pChildEl->get_CurrentName() failed", DBG);
			continue;
		}

		std::wstring wsWindowName(bWindowName, SysStringLen(bWindowName));

		if (wsWindowName.empty())
		{
			wsWindowName = L"<Empty>";
		}

		DWORD pid = Finder::GetPIDByUIAutomationElement(pChildEl);

		if (pid != -1)
		{
			Log(
				L"[" + std::to_wstring(i) + L"] " +
				L" | PID: " + std::to_wstring(pid) +
				L" | Name: " + GetModuleNameFromPid(pid) +
				L" | Window name: " + wsWindowName +
				L" |",
				EMPTY
			);
		}
		else {
			Log(
				L"[" + std::to_wstring(i) + L"] " +
				L"| PID: Unknown " +
				L"| Window name: Unknown |",
				EMPTY
			);
		}
	}

	return 0;
}


BOOL CALLBACK enum_windows_callback(HWND handle, LPARAM lParam)
{
	HANDLEDATA& data = *(HANDLEDATA*)lParam;
	unsigned long process_id = 0;
	GetWindowThreadProcessId(handle, &process_id);
	if (data.pid != process_id || !(GetWindow(handle, GW_OWNER) == (HWND)0 && IsWindowVisible(handle)))
		return TRUE;
	data.hwnd = handle;
	return FALSE;
}

IUIAutomationElement* Finder::GetUIAElementByPID(IUIAutomation* pAutomation, DWORD pid)
{
	IUIAutomationElement* pAutomationElement;

	HANDLEDATA data;
	data.pid = pid;
	data.hwnd = 0;

	EnumWindows(enum_windows_callback, (LPARAM)&data);

	if (data.hwnd == NULL)
	{
		Log(L"Cant find HWND", WARNING);
		return nullptr;
	}

	pAutomation->ElementFromHandle(data.hwnd, &pAutomationElement);
	return pAutomationElement;
}

IUIAutomationElement* Finder::GetUIAElementByName(IUIAutomation* pAutomation, wchar_t* windowName)
{
	HRESULT hr;
	CComPtr<IUIAutomationCondition> pCondition = NULL;
	IUIAutomationElement* pRootElement = NULL;
	CComPtr<IUIAutomationElementArray> pElementArray = NULL;

	VARIANT vWindowName;
	VariantInit(&vWindowName);
	vWindowName.vt = VT_BSTR;
	vWindowName.bstrVal = SysAllocString(windowName);

	hr = pAutomation->CreatePropertyCondition(UIA_NamePropertyId, vWindowName, &pCondition);

	if (FAILED(hr)) {
		Log(L"pAutomation->CreatePropertyCondition() failed", WARNING);
		PrintErrorFromHRESULT(hr);
		return nullptr;
	}

	hr = pAutomation->GetRootElement(&pRootElement);
	if (FAILED(hr)) {
		Log(L"pAutomation->GetRootElement() failed", WARNING);
		PrintErrorFromHRESULT(hr);
		return nullptr;
	}


	hr = pRootElement->FindAll(TreeScope_Children, pCondition, &pElementArray);
	if (FAILED(hr)) {
		Log(L"pRootElement->FindAll() failed", WARNING);
		PrintErrorFromHRESULT(hr);
		return nullptr;
	}

	int count = 0;
	hr = pElementArray->get_Length(&count);

	if (SUCCEEDED(hr) && count > 0) {
		CComPtr<IUIAutomationElement> pMainWindow = NULL;
		hr = pElementArray->GetElement(0, &pMainWindow);
		return pMainWindow;
	}

	return nullptr;
}