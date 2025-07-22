#pragma once
#include "shared/ctx.hpp"
#include "shared/util.hpp"
#include <print>
#include <thread>

#include <Windows.h>

namespace defendnot {
    template <typename... TArgs>
    void logln(const std::format_string<TArgs...> fmt, TArgs... args) noexcept {
        if (!shared::ctx.verbose) [[likely]] {
            return;
        }

        shared::alloc_console();
        std::println(stdout, fmt, std::forward<TArgs>(args)...);
    }
} // namespace defendnot
