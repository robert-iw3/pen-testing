#include "core/core.hpp"

#include "shared/defer.hpp"
#include "shared/native.hpp"

#include <print>
#include <stdexcept>

#include <Windows.h>

namespace loader {
    [[nodiscard]] HANDLE inject(std::string_view dll_path, std::string_view proc_name) {
        STARTUPINFOA si = {
            .cb = sizeof(si),
        };
        PROCESS_INFORMATION pi = {
            0,
        };
        SECURITY_ATTRIBUTES sa = {
            .nLength = sizeof(sa),
            .bInheritHandle = TRUE,
        };

        /// By setting ReadImageFileExecOptions to FALSE and attaching ourselves as a debugger we can skip the IFEO
        /// \xref: https://github.com/es3n1n/defendnot/issues/7#issuecomment-2874903650
        native::get_peb()->read_image_file_exec_options = 0;

        std::println("** booting {}", proc_name);
        const auto process_flags = CREATE_SUSPENDED | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS;
        if (!CreateProcessA(nullptr, const_cast<char*>(proc_name.data()), &sa, &sa, FALSE, process_flags, nullptr, nullptr, &si, &pi)) {
            throw std::runtime_error(std::format("unable to create process: {}", GetLastError()));
        }

        /// Detach
        native::debug_set_process_kill_on_exit(false);
        native::debug_active_process_stop(pi.dwProcessId);

        defer->void {
            CloseHandle(pi.hThread);
            /// Not closing hProcess because we return it
        };

        LPVOID mem = VirtualAllocEx(pi.hProcess, nullptr, dll_path.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mem == nullptr) {
            throw std::runtime_error(std::format("unable to allocate memory: {}", GetLastError()));
        }

        defer->void {
            VirtualFreeEx(pi.hProcess, mem, 0, MEM_RELEASE);
        };

        if (!WriteProcessMemory(pi.hProcess, mem, dll_path.data(), dll_path.size() + 1, nullptr)) {
            throw std::runtime_error(std::format("unable to write memory: {}", GetLastError()));
        }

        HANDLE thread = CreateRemoteThread(pi.hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), mem, 0, nullptr);
        if (thread == NULL) {
            throw std::runtime_error(std::format("unable to create thread: {}", GetLastError()));
        }

        defer->void {
            CloseHandle(thread);
        };

        /// Wait for DllMain to complete
        WaitForSingleObject(thread, INFINITE);
        return pi.hProcess;
    }
} // namespace loader
