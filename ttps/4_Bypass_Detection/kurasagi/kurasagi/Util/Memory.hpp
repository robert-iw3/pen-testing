/*
 * @file Memory.hpp
 * @brief Memory Utilities, like hooking or something.
 */

#pragma once

#include "../Include.hpp"

/*
 * @brief Write on Read-Only Memory.
 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
 */
BOOLEAN WriteOnReadOnlyMemory(PVOID src, PVOID dst, size_t size);

/*
 * @brief Determine if address is canonical.
 * @returns `TRUE` if the address is canonical, `FALSE` otherwise.
 */
BOOLEAN IsCanonicalAddress(PVOID address);

/*
 * @brief Make Non-canonical address to canonical address.
 * @returns `address` made to be canonical.
 */
PVOID MakeCanonicalAddress(PVOID address);

/*
 * @brief Get Pml4E's VA Type.
 * @returns `0xFF` if index was invalid, else the Pml4e's VA Type, based on _MI_SYSTEM_VA_TYPE.
 */
UCHAR GetPml4eVaType(size_t index);

/*
 * @brief Get PML4/PDPT/PD/PT Entry Pointer for virtual address. You can set it by level.
 * @param v: The address that you want to get.
 * @param level: 4 for PML4, 3 for PDPT, 2 for PD, 1 for PT.
 * @returns Page Table entry for virtual address. `NULL` if failed to get it
 */
UINT64* GetPageTableEntryPointer(PVOID v, size_t level);
UINT64* GetLastPageTableEntryPointer(PVOID v);

#define FlushTlb __writecr3(__readcr3())

/*
 * @brief Get Pml4 index of address.
 */
size_t GetPml4Index(PVOID address);

/*
 * @brief Determine if the address is valid.
 * @return `TRUE` if valid, `FALSE` otherwise.
 */
BOOLEAN IsValidAddress(PVOID address);

namespace Hook {

	/*
	 * @brief Trampoline hook `hookFunction`.
	 * @details `gateway` SHOULD be a function with over than 32 opcodes.
	 * @return `TRUE` if operation was successful.
	 */
	BOOLEAN HookTrampoline(PVOID origFunction, PVOID hookFunction, PVOID gateway, size_t len);

}