#include "Errors.h"
#include "Logger.h"

void PrintErrorFromHRESULT(HRESULT hr) {
	_com_error err(hr);
	LPCTSTR errMsg = err.ErrorMessage();
	Log(L"[-] Err msg: " + std::wstring(errMsg), WARNING);
}
