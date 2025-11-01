#pragma once
#include <Windows.h>
#include <iostream>
#include <comdef.h>
#include <UIAutomationClient.h>
#include <fstream>
#include <codecvt>
#include <locale>
#include <mutex>
#include <io.h>
#include <fcntl.h>
#include <string>

extern std::wstring g_LogFileName;
extern bool g_DebugModeEnable;

enum LogLevel {
    EMPTY,
    INFO,
    DBG,
    WARNING
};

using LogSinkW = void(*)(const std::wstring& line);
extern LogSinkW g_LogSink;
inline void SetLogSink(LogSinkW sink) { g_LogSink = sink; }

void Log(const std::wstring& message, LogLevel level);
