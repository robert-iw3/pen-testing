#include "spy_api.h"

#include <windows.h>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include "start.h"

#include "Finder.h"
#include "Errors.h"
#include "Logger.h"
#include "EventHandler.h"
#include "ChangedEventHandler.h"
#include "Tree.h"

bool g_IgnoreHandlers = false;
MyTreeWalker* g_pMyTreeWalker = NULL;
std::wstring g_LogFileName = L"";
bool g_DebugModeEnable = false;

namespace {
    std::atomic<bool> g_running{false};
    std::thread g_worker;

    std::mutex g_mx;
    std::queue<std::wstring> g_lines;
    constexpr size_t MAX_LINES = 20000;
    void PushLineW(const std::wstring& line) {
        std::lock_guard<std::mutex> lk(g_mx);
        g_lines.push(line);
        while (g_lines.size() > MAX_LINES) g_lines.pop();
    }
    extern LogSinkW g_LogSink;

void SpyWorker(const wchar_t* window_name_w,
               uint32_t pid,
               int timeout_sec,
               bool no_uia_events,
               bool no_property_events,
               bool enable_debug)
{
    g_DebugModeEnable = enable_debug;
    g_IgnoreHandlers  = false;
    g_LogFileName.clear();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        PushLineW(L"[ERR] CoInitializeEx() failed");
        PrintErrorFromHRESULT(hr);
        return;
    }

    IUIAutomation* pAutomation = NULL;
    IUIAutomationElement* pAutomationElement = NULL;

    hr = CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER,
                          __uuidof(IUIAutomation), (void**)&pAutomation);
    if (FAILED(hr)) {
        PushLineW(L"[ERR] CoCreateInstance(CUIAutomation) failed");
        PrintErrorFromHRESULT(hr);
        CoUninitialize();
        return;
    }

    std::thread automationThread;
    std::thread propertyChangedThread;
    SetLogSink(&PushLineW);
    if (window_name_w && *window_name_w) {
        pAutomationElement = Finder::GetUIAElementByName(pAutomation, const_cast<wchar_t*>(window_name_w));
        if (pAutomationElement == NULL) {
            Log(L"Cant find GUI by windowname!!!. Try to use --pid", WARNING);
            goto cleanup;
        }
        Log(L"Spying " + std::wstring(window_name_w), DBG);
    } else if (pid != 0) {
        pAutomationElement = Finder::GetUIAElementByPID(pAutomation, pid);
        if (pAutomationElement == NULL) {
            Log(L"Cant find GUI by pid!!!. Try to use --windowname", WARNING);
            goto cleanup;
        }
        Log(L"Spying " + std::to_wstring(pid), DBG);
    } else {
    }

    g_pMyTreeWalker = new MyTreeWalker(pAutomation);

    if (!no_uia_events) {
        automationThread = std::thread(MyAutomationEventHandler::Deploy,
                                       pAutomation, pAutomationElement, timeout_sec);
    }
    if (!no_property_events) {
        propertyChangedThread = std::thread(MyPropertyChangedEventHandler::Deploy,
                                            pAutomation, pAutomationElement, timeout_sec);
    }

    while (g_running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (automationThread.joinable())      automationThread.join();
    if (propertyChangedThread.joinable()) propertyChangedThread.join();

cleanup:
    if (g_pMyTreeWalker) {
        delete g_pMyTreeWalker;
        g_pMyTreeWalker = nullptr;
    }
    if (pAutomationElement) pAutomationElement->Release();
    if (pAutomation)        pAutomation->Release();

    SetLogSink(nullptr);
    CoUninitialize();

    PushLineW(L"[INFO] Stopped.");
}
} // namespace

int spy_start(const wchar_t* window_name_w,
              uint32_t pid,
              int timeout_sec,
              int set_no_uia_events,
              int set_no_property_events,
              int enable_debug)
{
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) {
        return 1;
    }
    try {
        g_worker = std::thread(SpyWorker,
                               window_name_w ? window_name_w : L"",
                               pid,
                               timeout_sec,
                               !!set_no_uia_events,
                               !!set_no_property_events,
                               !!enable_debug);
    } catch (...) {
        g_running.store(false);
        return 2;
    }
    return 0;
}

void spy_stop(void) {
    if (!g_running.exchange(false)) return;
    if (g_worker.joinable()) g_worker.join();
}

size_t spy_read_line_w(wchar_t* out, size_t out_cap) {
    if (!out || out_cap == 0) return 0;
    std::wstring line;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        if (g_lines.empty()) return 0;
        line = std::move(g_lines.front());
        g_lines.pop();
    }
    size_t n = line.size();
    if (n >= out_cap) n = out_cap - 1;
    wmemcpy(out, line.c_str(), n);
    out[n] = L'\0';
    return n;
}
