#pragma once
#include <Windows.h>
#include <iostream>
#include <UIAutomationClient.h>
#include <unordered_map>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <algorithm>


class Helpers {
public:
	static void HideWindow(HWND hwnd);
	static void CreateOverlay(HWND hwnd, HWND* overLayHwnd);
	static void RemoveOverlay(HWND);
	static HRESULT GetClipBoardData(std::wstring& clipboardData);
	static std::wstring ControlTypeIdToString(CONTROLTYPEID controlTypeId);
	static std::wstring EventIdToString(EVENTID eventID);
	static uint32_t hash(const std::wstring& data) noexcept;
	static std::wstring GetApplicationName(const std::wstring& fullPath);
	static std::wstring GetCurrentDateTime();
	static std::wstring HandleVariant(VARIANT vVar);
	static std::wstring ConvertToLower(const std::wstring& string);
	static std::wstring GetDomainFromUrl(const std::wstring& url);
};