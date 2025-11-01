#pragma once
#include <Windows.h>
#include <UIAutomationClient.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <vector>
#include <Psapi.h>
#include <atlbase.h>


static class Finder {
public:
	static ULONG DisplayActiveWindows();
	static std::wstring GetModuleNameFromPid(DWORD pid);
	static IUIAutomationElement* GetUIAElementByPID(IUIAutomation* pAutomation, DWORD pid);
	static IUIAutomationElement* GetUIAElementByName(IUIAutomation* pAutomation, wchar_t* windowName);
	static DWORD GetPIDByUIAutomationElement(IUIAutomationElement* pAutomationElement);
};

struct HANDLEDATA {
	unsigned long pid;
	HWND hwnd;
};
