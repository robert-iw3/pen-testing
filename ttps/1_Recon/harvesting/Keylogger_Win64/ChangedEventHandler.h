#pragma once
#include <Windows.h>
#include <UIAutomationClient.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <vector>
#include <atlbase.h>
#include <functional>
#include <unordered_map>
#include <chrono>

extern bool g_IgnoreHandlers;

class MyPropertyChangedEventHandler : public IUIAutomationPropertyChangedEventHandler {
private:
	ULONG refCount = 0;
	ULONG eventCount = 0;
	std::wstring oldTextValue = L"";
	std::chrono::seconds eventTimeout = std::chrono::seconds(1);

	void HandleOther(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsDate, PROPERTYID propId, VARIANT vVar);

	void HandleKeepass(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsDate, PROPERTYID propId, VARIANT vVar);
	BSTR previousDb = NULL;

	void HandleChrome(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsDate, PROPERTYID propId, VARIANT vVar);

public:
	std::chrono::steady_clock::time_point lastEventTime;

	MyPropertyChangedEventHandler();
	ULONG STDMETHODCALLTYPE AddRef();
	ULONG STDMETHODCALLTYPE Release();
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppInterface);
	ULONG STDMETHODCALLTYPE GetEventCount();
	void STDMETHODCALLTYPE IncrementEventCount();
	void STDMETHODCALLTYPE SetEventTimeout(int);
	std::chrono::seconds STDMETHODCALLTYPE GetEventTimeout();
	HRESULT STDMETHODCALLTYPE HandlePropertyChangedEvent(IUIAutomationElement*, PROPERTYID, VARIANT);
	static HRESULT STDMETHODCALLTYPE Deploy(IUIAutomation*, IUIAutomationElement*, int);
};


