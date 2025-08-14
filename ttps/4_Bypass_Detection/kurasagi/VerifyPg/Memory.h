#pragma once

#include "Include.h"

/*
 * @brief Write on Read-Only Memory.
 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
 */
BOOLEAN WriteOnReadOnlyMemory(PVOID src, PVOID dst, size_t size);

/*
 * @brief Trampoline hook `hookFunction`.
 * @details `gateway` SHOULD be a function with over than 32 opcodes.
 * @return `TRUE` if operation was successful.
 */
BOOLEAN HookTrampoline(PVOID origFunction, PVOID hookFunction, PVOID gateway, size_t len);