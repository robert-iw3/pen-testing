#include "Tree.h"
#include "Logger.h"
#include "Errors.h"

MyTreeWalker::MyTreeWalker(IUIAutomation* pUIAutomation)
{
	if (pUIAutomation == NULL)
	{
		Log(L"Failed to create TreeWalker. pUIAutomation was NULL", WARNING);
		return;
	}

	pAutomation = pUIAutomation;

	HRESULT hr = pUIAutomation->get_RawViewWalker(&pWalker);
	if (FAILED(hr))
	{
		Log(L"Failed to create TreeWalker.", WARNING);
		PrintErrorFromHRESULT(hr);
		return;
	}
}

HRESULT MyTreeWalker::GetFirstAscendingWindowName(IUIAutomationElement* pAutomationElementChild, BSTR* bWindowName)
{
	if (bWindowName == NULL)
	{
		return E_POINTER;
	}
	CComPtr<IUIAutomationElement> pAutomationElementParent;
	HRESULT hr = pAutomationElementChild->get_CurrentName(bWindowName);
	if (SUCCEEDED(hr) && SysStringLen(*bWindowName) == 0)
	{
		while (true) {
			pAutomationElementParent = g_pMyTreeWalker->GetParent(pAutomationElementChild);
			if (!pAutomationElementParent)
			{
				Log(L"Can't find parent element", DBG);
				return E_APPLICATION_VIEW_EXITING;
			}

			hr = pAutomationElementParent->get_CurrentName(bWindowName);
			if (FAILED(hr))
			{
				Log(L"Failed to get parent name", DBG);
				return E_APPLICATION_VIEW_EXITING;
			}

			if (SysStringLen(*bWindowName) != 0)
			{
				break;
			}

			pAutomationElementChild = pAutomationElementParent;
		}
	}
	return S_OK;
}

MyTreeWalker::~MyTreeWalker()
{
	if (pWalker != NULL)
	{
		pWalker->Release();
	}
}

IUIAutomationElement* MyTreeWalker::GetParent(IUIAutomationElement* pChild)
{
	IUIAutomationElement* pParent = NULL;

	if (pWalker == NULL)
	{
		Log(L"pWalker was null", WARNING);
		return pParent;
	}

	HRESULT hr = pWalker->GetParentElement(pChild, &pParent);
	if (FAILED(hr))
	{
		Log(L"Failed to get parent.", WARNING);
		PrintErrorFromHRESULT(hr);
	}
	return pParent;
}

IUIAutomationElement* MyTreeWalker::FindFirstAscending(IUIAutomationElement* pStartElement, IUIAutomationCondition* pAutomationCondition)
{
	CComPtr<IUIAutomationElement> pCurrentElement = GetParent(pStartElement);

	IUIAutomationElement* pFoundElement = NULL;

	while (pFoundElement == NULL) {

		if (pCurrentElement == NULL)
			return NULL;

		BOOL isMatch = FALSE;

		HRESULT hr = pCurrentElement->FindFirst(TreeScope_Subtree, pAutomationCondition, &pFoundElement);
		if (SUCCEEDED(hr) && pFoundElement != NULL) {
			return pFoundElement;
		}

		pCurrentElement = GetParent(pCurrentElement);
	}

	return NULL;
}

IUIAutomation* MyTreeWalker::GetPAutomation()
{
	return pAutomation;
}

IUIAutomationTreeWalker* MyTreeWalker::GetPTreeWalker()
{
	return pWalker;
}