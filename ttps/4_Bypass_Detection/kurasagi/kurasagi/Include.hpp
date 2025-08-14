/*
 * @file Include.hpp
 * @brief Header file to include necessary Windows kernel headers and definitions.
 */

#pragma once

#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <stdarg.h>
#include <ntstrsafe.h>

extern "C"
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_same_ VOID
KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);

extern "C"
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ VOID
KeSignalCallDpcDone(_In_ PVOID SystemArgument1);

extern "C"
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ LOGICAL
KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);