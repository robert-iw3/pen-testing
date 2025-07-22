#include "bootstrap/bootstrap.hpp"
#include "core/log.hpp"
#include "shared/ipc.hpp"

#include <stdexcept>
#include <thread>

#include <Windows.h>

namespace {
    void entry_thread(HMODULE base) {
        bool success = false;
        std::unique_ptr<shared::InterProcessCommunication> ipc;

        try {
            /// Open IPC handle
            ipc = std::make_unique<shared::InterProcessCommunication>(shared::InterProcessCommunicationMode::WRITE);

            /// Invoke the real entry
            defendnot::startup();
            success = true;
        } catch (std::exception& err) {
            MessageBoxA(nullptr, err.what(), "defendnot", MB_TOPMOST | MB_ICONERROR);
        }

        if (ipc) {
            (*ipc)->success = success;
            (*ipc)->finished = true;
        }

        /// Always free out module once we are done
        FreeLibraryAndExitThread(base, 0);
    }
} // namespace

BOOL __stdcall DllMain(HINSTANCE base, std::uint32_t call_reason, LPVOID reserved) {
    if (call_reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    const auto th = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entry_thread), base, 0, nullptr);
    if (th != nullptr) {
        CloseHandle(th);
    }

    return TRUE;
}
