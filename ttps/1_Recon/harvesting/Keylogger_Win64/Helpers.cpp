#include "Helpers.h"

LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_NCCREATE:
    case WM_NCMOUSEMOVE:
    case WM_COMMAND:
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        HBRUSH hBrush = CreateSolidBrush(RGB(192, 192, 192)); // grey color
        FillRect(hdc, &ps.rcPaint, hBrush);
        DeleteObject(hBrush);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void Helpers::HideWindow(HWND hwnd)
{
    if (hwnd != NULL)
        ShowWindow(hwnd, SW_HIDE);
}

void Helpers::CreateOverlay(HWND hwnd, HWND* pOverlayWnd)
{
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = OverlayWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"OverlayClass";
    RegisterClass(&wc);

    RECT rect;

    GetWindowRect(hwnd, &rect);

    *pOverlayWnd = CreateWindowEx(
        WS_EX_OVERLAPPEDWINDOW,
        L"OverlayClass", L"Overlay", WS_POPUP,
        rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
        NULL, NULL, wc.hInstance, NULL
    );


   // SetLayeredWindowAttributes(*pOverlayWnd, RGB(192, 192, 192), 255, LWA_COLORKEY);

    SetWindowPos(*pOverlayWnd, HWND_TOPMOST, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, SWP_SHOWWINDOW);
    ShowWindow(*pOverlayWnd, SW_SHOW);
}

void Helpers::RemoveOverlay(HWND hwnd)
{
    if (hwnd)
        DestroyWindow(hwnd);
}

HRESULT Helpers::GetClipBoardData(std::wstring& clipboardData) {
    if (!OpenClipboard(NULL)) {

        return HRESULT_FROM_WIN32(GetLastError());

    }
    HGLOBAL hData = GetClipboardData(CF_UNICODETEXT);
    if (hData != NULL) {
        wchar_t* pData = static_cast<wchar_t*>(GlobalLock(hData));
        if (pData != NULL) {
            clipboardData = pData;
            GlobalUnlock(hData);
        }
    }

    CloseClipboard();
    return S_OK;
}

std::wstring Helpers::ControlTypeIdToString(CONTROLTYPEID controlTypeId)
{
	static const std::unordered_map<CONTROLTYPEID, std::wstring> controlTypeIdMap = {
		{ UIA_AnnotationAnnotationTypeIdPropertyId, L"UIA_AnnotationAnnotationTypeIdPropertyId" },
		{ UIA_AnnotationAnnotationTypeNamePropertyId, L"UIA_AnnotationAnnotationTypeNamePropertyId" },
		{ UIA_AnnotationAuthorPropertyId, L"UIA_AnnotationAuthorPropertyId" },
		{ UIA_AnnotationDateTimePropertyId, L"UIA_AnnotationDateTimePropertyId" },
		{ UIA_AnnotationTargetPropertyId, L"UIA_AnnotationTargetPropertyId" },
		{ UIA_DockDockPositionPropertyId, L"UIA_DockDockPositionPropertyId" },
		{ UIA_DragDropEffectPropertyId, L"UIA_DragDropEffectPropertyId" },
		{ UIA_DragDropEffectsPropertyId, L"UIA_DragDropEffectsPropertyId" },
		{ UIA_DragIsGrabbedPropertyId, L"UIA_DragIsGrabbedPropertyId" },
		{ UIA_DragGrabbedItemsPropertyId, L"UIA_DragGrabbedItemsPropertyId" },
		{ UIA_DropTargetDropTargetEffectPropertyId, L"UIA_DropTargetDropTargetEffectPropertyId" },
		{ UIA_DropTargetDropTargetEffectsPropertyId, L"UIA_DropTargetDropTargetEffectsPropertyId" },
		{ UIA_ExpandCollapseExpandCollapseStatePropertyId, L"UIA_ExpandCollapseExpandCollapseStatePropertyId" },
		{ UIA_GridColumnCountPropertyId, L"UIA_GridColumnCountPropertyId" },
		{ UIA_GridItemColumnPropertyId, L"UIA_GridItemColumnPropertyId" },
		{ UIA_GridItemColumnSpanPropertyId, L"UIA_GridItemColumnSpanPropertyId" },
		{ UIA_GridItemContainingGridPropertyId, L"UIA_GridItemContainingGridPropertyId" },
		{ UIA_GridItemRowPropertyId, L"UIA_GridItemRowPropertyId" },
		{ UIA_GridItemRowSpanPropertyId, L"UIA_GridItemRowSpanPropertyId" },
		{ UIA_GridRowCountPropertyId, L"UIA_GridRowCountPropertyId" },
		{ UIA_LegacyIAccessibleChildIdPropertyId, L"UIA_LegacyIAccessibleChildIdPropertyId" },
		{ UIA_LegacyIAccessibleDefaultActionPropertyId, L"UIA_LegacyIAccessibleDefaultActionPropertyId" },
		{ UIA_LegacyIAccessibleDescriptionPropertyId, L"UIA_LegacyIAccessibleDescriptionPropertyId" },
		{ UIA_LegacyIAccessibleHelpPropertyId, L"UIA_LegacyIAccessibleHelpPropertyId" },
		{ UIA_LegacyIAccessibleKeyboardShortcutPropertyId, L"UIA_LegacyIAccessibleKeyboardShortcutPropertyId" },
		{ UIA_LegacyIAccessibleNamePropertyId, L"UIA_LegacyIAccessibleNamePropertyId" },
		{ UIA_LegacyIAccessibleRolePropertyId, L"UIA_LegacyIAccessibleRolePropertyId" },
		{ UIA_LegacyIAccessibleSelectionPropertyId, L"UIA_LegacyIAccessibleSelectionPropertyId" },
		{ UIA_LegacyIAccessibleStatePropertyId, L"UIA_LegacyIAccessibleStatePropertyId" },
		{ UIA_LegacyIAccessibleValuePropertyId, L"UIA_LegacyIAccessibleValuePropertyId" },
		{ UIA_MultipleViewCurrentViewPropertyId, L"UIA_MultipleViewCurrentViewPropertyId" },
		{ UIA_MultipleViewSupportedViewsPropertyId, L"UIA_MultipleViewSupportedViewsPropertyId" },
		{ UIA_RangeValueIsReadOnlyPropertyId, L"UIA_RangeValueIsReadOnlyPropertyId" },
		{ UIA_RangeValueLargeChangePropertyId, L"UIA_RangeValueLargeChangePropertyId" },
		{ UIA_RangeValueMaximumPropertyId, L"UIA_RangeValueMaximumProperty Id" },
		{ UIA_RangeValueMinimumPropertyId, L"UIA_RangeValueMinimumPropertyId" },
		{ UIA_RangeValueSmallChangePropertyId, L"UIA_RangeValueSmallChangePropertyId" },
		{ UIA_RangeValueValuePropertyId, L"UIA_RangeValueValuePropertyId" },
		{ UIA_ScrollHorizontalScrollPercentPropertyId, L"UIA_ScrollHorizontalScrollPercentPropertyId" },
		{ UIA_ScrollHorizontalViewSizePropertyId, L"UIA_ScrollHorizontalViewSizePropertyId" },
		{ UIA_ScrollVerticalScrollPercentPropertyId, L"UIA_ScrollVerticalScrollPercentPropertyId" },
		{ UIA_ScrollVerticalViewSizePropertyId, L"UIA_ScrollVerticalViewSizePropertyId" },
		{ UIA_SelectionSelectionPropertyId, L"UIA_SelectionSelectionPropertyId" },
		{ UIA_SelectionCanSelectMultiplePropertyId, L"UIA_SelectionCanSelectMultiplePropertyId" },
		{ UIA_SelectionIsSelectionRequiredPropertyId, L"UIA_SelectionIsSelectionRequiredPropertyId" },
		{ UIA_TableColumnHeadersPropertyId, L"UIA_TableColumnHeadersPropertyId" },
		{ UIA_TableItemColumnHeaderItemsPropertyId, L"UIA_TableItemColumnHeaderItemsPropertyId" },
		{ UIA_TableItemRowHeaderItemsPropertyId, L"UIA_TableItemRowHeaderItemsPropertyId" },
		{ UIA_TableRowHeadersPropertyId, L"UIA_TableRowHeadersPropertyId" },
		{ UIA_TextControlTypeId, L"UIA_TextControlTypeId" },
		{ UIA_ValueValuePropertyId, L"UIA_ValueValuePropertyId" },
		{ UIA_WindowCanMaximizePropertyId, L"UIA_WindowCanMaximizePropertyId" },
		{ UIA_WindowCanMinimizePropertyId, L"UIA_WindowCanMinimizePropertyId" },
		{ UIA_WindowIsModalPropertyId, L"UIA_WindowIsModalPropertyId" },
		{ UIA_WindowIsTopmostPropertyId, L"UIA_WindowIsTopmostPropertyId" },
		{ UIA_WindowWindowInteractionStatePropertyId, L"UIA_WindowWindowInteractionStatePropertyId" },
		{ UIA_WindowWindowVisualStatePropertyId, L"UIA_WindowWindowVisualStatePropertyId" }
	};

	auto it = controlTypeIdMap.find(controlTypeId);
	if (it != controlTypeIdMap.end()) {
		return it->second;
	}
	return L"Unknown Control Type";
}

std::wstring Helpers::EventIdToString(EVENTID eventID) {

	static const std::unordered_map<EVENTID, std::wstring> eventIdMap = {
		{ UIA_ActiveTextPositionChangedEventId, L"UIA_ActiveTextPositionChangedEventId" },
		{ UIA_AsyncContentLoadedEventId, L"UIA_AsyncContentLoadedEventId" },
		{ UIA_AutomationFocusChangedEventId, L"UIA_AutomationFocusChangedEventId" },
		{ UIA_AutomationPropertyChangedEventId, L"UIA_AutomationPropertyChangedEventId" },
		{ UIA_ChangesEventId, L"UIA_ChangesEventId" },
		{ UIA_Drag_DragCancelEventId, L"UIA_Drag_DragCancelEventId" },
		{ UIA_Drag_DragCompleteEventId, L"UIA_Drag_DragCompleteEventId" },
		{ UIA_Drag_DragStartEventId, L"UIA_Drag_DragStartEventId" },
		{ UIA_DropTarget_DragEnterEventId, L"UIA_DropTarget_DragEnterEventId" },
		{ UIA_DropTarget_DragLeaveEventId, L"UIA_DropTarget_DragLeaveEventId" },
		{ UIA_DropTarget_DroppedEventId, L"UIA_DropTarget_DroppedEventId" },
		{ UIA_HostedFragmentRootsInvalidatedEventId, L"UIA_HostedFragmentRootsInvalidatedEventId" },
		{ UIA_InputDiscardedEventId, L"UIA_InputDiscardedEventId" },
		{ UIA_InputReachedOtherElementEventId, L"UIA_InputReachedOtherElementEventId" },
		{ UIA_InputReachedTargetEventId, L"UIA_InputReachedTargetEventId" },
		{ UIA_Invoke_InvokedEventId, L"UIA_Invoke_InvokedEventId" },
		{ UIA_LayoutInvalidatedEventId, L"UIA_LayoutInvalidatedEventId" },
		{ UIA_LiveRegionChangedEventId, L"UIA_LiveRegionChangedEventId" },
		{ UIA_MenuClosedEventId, L"UIA_MenuClosedEventId" },
		{ UIA_MenuModeEndEventId, L"UIA_MenuModeEndEventId" },
		{ UIA_MenuModeStartEventId, L"UIA_MenuModeStartEventId" },
		{ UIA_MenuOpenedEventId, L"UIA_MenuOpenedEventId" },
		{ UIA_NotificationEventId, L"UIA_NotificationEventId" },
		{ UIA_Selection_InvalidatedEventId, L"UIA_Selection_InvalidatedEventId" },
		{ UIA_SelectionItem_ElementAddedToSelectionEventId, L"UIA_SelectionItem_ElementAddedToSelectionEventId" },
		{ UIA_SelectionItem_ElementRemovedFromSelectionEventId, L"UIA_SelectionItem_ElementRemovedFromSelectionEventId" },
		{ UIA_SelectionItem_ElementSelectedEventId, L"UIA_SelectionItem_ElementSelectedEventId" },
		{ UIA_StructureChangedEventId, L"UIA_StructureChangedEventId" },
		{ UIA_SystemAlertEventId, L"UIA_SystemAlertEventId" },
		{ UIA_Text_TextChangedEventId, L"UIA_Text_TextChangedEventId" },
		{ UIA_Text_TextSelectionChangedEventId, L"UIA_Text_TextSelectionChangedEventId" },
		{ UIA_TextEdit_ConversionTargetChangedEventId, L"UIA_TextEdit_ConversionTargetChangedEventId" },
		{ UIA_TextEdit_TextChangedEventId, L"UIA_TextEdit_TextChangedEventId" },
		{ UIA_ToolTipClosedEventId, L"UIA_ToolTipClosedEventId" },
		{ UIA_ToolTipOpenedEventId, L"UIA_ToolTipOpenedEventId" },
		{ UIA_Window_WindowClosedEventId, L"UIA_Window_WindowClosedEventId" },
		{ UIA_Window_WindowOpenedEventId, L"UIA_Window_WindowOpenedEventId" }
	};

	auto it = eventIdMap.find(eventID);
	if (it != eventIdMap.end()) {
		return it->second;
	}
	else {
		return L"Unknown Event";
	}
}

uint32_t Helpers::hash(const std::wstring& data) noexcept {
	uint32_t hash = 5381;

	for (wchar_t c : data) {
		hash = ((hash << 5) + hash) + static_cast<uint32_t>(c);
	}

	return hash;
}

std::wstring Helpers::GetApplicationName(const std::wstring& fullPath) {
	size_t lastSlashPos = fullPath.find_last_of(L"\\");
	if (lastSlashPos != std::wstring::npos) {
		return fullPath.substr(lastSlashPos + 1);

	}
	return fullPath;
}

std::wstring Helpers::GetCurrentDateTime() {
	auto now = std::chrono::system_clock::now();
	std::time_t now_c = std::chrono::system_clock::to_time_t(now);

	std::tm localTime;
	localtime_s(&localTime, &now_c);


	std::wostringstream oss;
	oss << L'['
		<< std::put_time(&localTime, L"%Y-%m-%d")
		<< L" | "
		<< std::put_time(&localTime, L"%H:%M:%S")
		<< L']';

	return oss.str();
}

std::wstring Helpers::HandleVariant(VARIANT vVar) {
    std::wstring result;

    if (vVar.vt == VT_EMPTY) {
        result = L"Variant is empty.";
        return result;
    }

    switch (vVar.vt) {
    case VT_NULL:
        result = L"Variant is NULL.";
        break;
    case VT_I2:
        result = L"Variant is int16: " + std::to_wstring(vVar.iVal);
        break;
    case VT_I4:
        result = L"Variant is int32: " + std::to_wstring(vVar.lVal);
        break;
    case VT_R4:
        result = L"Variant is float: " + std::to_wstring(vVar.fltVal);
        break;
    case VT_R8:
        result = L"Variant is double: " + std::to_wstring(vVar.dblVal);
        break;
    case VT_CY:
        result = L"Variant is currency: " + std::to_wstring(vVar.cyVal.int64);
        break;
    case VT_DATE:
        result = L"Variant is date: " + std::to_wstring(vVar.date);
        break;
    case VT_BSTR:
        result = L"Variant is BSTR: " + std::wstring(vVar.bstrVal);
        break;
    case VT_DISPATCH:
        result = L"Variant is IDispatch.";
        break;
    case VT_ERROR:
        result = L"Variant is error: " + std::to_wstring(vVar.scode);
        break;
    case VT_BOOL:
        result = L"Variant is bool: " + std::wstring(vVar.boolVal ? L"true" : L"false");
        break;
    case VT_VARIANT:
        result = L"Variant is another variant.";
        break;
    case VT_UNKNOWN:
        result = L"Variant is IUnknown.";
        break;
    case VT_DECIMAL:
        result = L"Variant is decimal.";
        break;
    case VT_I1:
        result = L"Variant is int8: " + std::to_wstring(static_cast<int>(vVar.bVal));
        break;
    case VT_UI1:
        result = L"Variant is uint8: " + std::to_wstring(static_cast<unsigned int>(vVar.bVal));
        break;
    case VT_UI2:
        result = L"Variant is uint16: " + std::to_wstring(vVar.uiVal);
        break;
    case VT_UI4:
        result = L"Variant is uint32: " + std::to_wstring(vVar.ulVal);
        break;
    case VT_I8:
        result = L"Variant is int64: " + std::to_wstring(vVar.llVal);
        break;
    case VT_UI8:
        result = L"Variant is uint64: " + std::to_wstring(vVar.ullVal);
        break;
    case VT_INT:
        result = L"Variant is int: " + std::to_wstring(vVar.intVal);
        break;
    case VT_UINT:
        result = L"Variant is uint: " + std::to_wstring(vVar.uintVal);
        break;
    case VT_VOID:
        result = L"Variant is void.";
        break;
    case VT_HRESULT:
        result = L"Variant is HRESULT: " + std::to_wstring(vVar.scode);
        break;
    case VT_PTR:
        result = L"Variant is pointer.";
        break;
    case VT_SAFEARRAY:
        result = L"Variant is SAFEARRAY.";
        break;
    case VT_CARRAY:
        result = L"Variant is C array.";
        break;
    case VT_USERDEFINED:
        result = L"Variant is user-defined type.";
        break;
    case VT_LPSTR:
        result = L"Variant is LPSTR.";
        break;
    case VT_LPWSTR:
        result = L"Variant is LPWSTR.";
        break;
    case VT_RECORD:
        result = L"Variant is RECORD.";
        break;
    case VT_INT_PTR:
        result = L"Variant is INT_PTR.";
        break;
    case VT_UINT_PTR:
        result = L"Variant is UINT_PTR.";
        break;
    case VT_FILETIME:
        result = L"Variant is FILETIME.";
        break;
    case VT_BLOB:
        result = L"Variant is BLOB.";
        break;
    case VT_STREAM:
        result = L"Variant is STREAM.";
        break;
    case VT_STORAGE:
        result = L"Variant is STORAGE.";
        break;
    case VT_STREAMED_OBJECT:
        result = L"Variant is STREAMED_OBJECT.";
        break;
    case VT_STORED_OBJECT:
        result = L"Variant is STORED_OBJECT.";
        break;
    case VT_BLOB_OBJECT:
        result = L"Variant is BLOB_OBJECT.";
        break;
    case VT_CF:
        result = L"Variant is CF.";
        break;
    case VT_CLSID:
        result = L"Variant is CLSID.";
        break;
    case VT_VERSIONED_STREAM:
        result = L"Variant is VERSIONED_STREAM.";
        break;
    case VT_BSTR_BLOB:
        result = L"Variant is BSTR_BLOB.";
        break;
    case VT_VECTOR:
        result = L"Variant is VECTOR.";
        break;
    case VT_ARRAY:
        result = L"Variant is ARRAY.";
        break;
    case VT_BYREF:
        result = L"Variant is BYREF.";
        break;
    case VT_RESERVED:
        result = L"Variant is RESERVED.";
        break;
    case VT_ILLEGAL:
        result = L"Variant is ILLEGAL.";
        break;
    default:
        result = L"Variant is of unknown type.";
        break;
    }

    return result;
}

std::wstring Helpers::ConvertToLower(const std::wstring& input)
{
	std::wstring output = input;
	std::transform(input.begin(), input.end(), output.begin(), ::tolower);
	return output;
}

std::wstring Helpers::GetDomainFromUrl(const std::wstring& url) {
	std::wstring domain = url;
	size_t pos = domain.find(L"://");
	if (pos != std::wstring::npos) {
		domain = domain.substr(pos + 3);
	}

	pos = domain.find(L"/");
	if (pos != std::wstring::npos) {
		domain = domain.substr(0, pos);
	}
	pos = domain.find(L":");
	if (pos != std::wstring::npos) {
		domain = domain.substr(0, pos);
	}
	return domain;
}
