#pragma once
#include <Windows.h>
#include <UIAutomationClient.h>
#include <atlbase.h>

class MyTreeWalker
{
private:
	IUIAutomation* pAutomation = NULL;
	IUIAutomationTreeWalker* pWalker = NULL;

public:
	MyTreeWalker(IUIAutomation*);
	~MyTreeWalker();
	HRESULT GetFirstAscendingWindowName(IUIAutomationElement* pAutomationElement, BSTR* bWindowName);
	IUIAutomationElement* GetParent(IUIAutomationElement* child);
	IUIAutomationElement* FindFirstAscending(IUIAutomationElement* pStartElement, IUIAutomationCondition* pAutomationCondition);
	IUIAutomation* GetPAutomation();
	IUIAutomationTreeWalker* GetPTreeWalker();
};

extern MyTreeWalker* g_pMyTreeWalker;
