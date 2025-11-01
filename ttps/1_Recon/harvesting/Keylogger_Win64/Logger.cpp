#include "Logger.h"

std::mutex logMutex;

LogSinkW g_LogSink = nullptr;

void Log(const std::wstring& message, LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex);

    std::wstring finalLine;
    switch (level) {
        case EMPTY:   finalLine = message; break;
        case INFO:    finalLine = L"[INFO] "    + message; break;
        case DBG:     if (g_DebugModeEnable) finalLine = L"[DEBUG] "   + message; break;
        case WARNING: finalLine = L"[WARNING] " + message; break;
        default: break;
    }
    if (finalLine.empty() && level == DBG && !g_DebugModeEnable) {
        return;
    }

    if (g_LogSink) {
        if (!g_LogFileName.empty()) {
            FILE* logFile = nullptr;
            if (_wfopen_s(&logFile, g_LogFileName.c_str(), L"a, ccs=UTF-16LE") == 0 && logFile) {
                _setmode(_fileno(logFile), _O_U16TEXT);
                fwprintf(logFile, L"%ls\n", finalLine.c_str());
                fclose(logFile);
            } else {
            }
        }
        g_LogSink(finalLine);
        return;
    }

    if (!g_LogFileName.empty()) {
        FILE* logFile = nullptr;
        errno_t err = _wfopen_s(&logFile, g_LogFileName.c_str(), L"a, ccs=UTF-16LE");
        if (logFile == nullptr || err != 0) {
            std::wcout << L"Can't create logfile" << std::endl;
            return;
        }
        _setmode(_fileno(logFile), _O_U16TEXT);
        fwprintf(logFile, L"%ls\n", finalLine.c_str());
        fclose(logFile);
    } else {
        std::wcout << finalLine << std::endl;
    }
}
