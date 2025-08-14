/*
 * @file Entry.c
 * @brief Entry point for the VerifyPg driver.
 */

#include "Include.h"
#include "Memory.h"

size_t ExQueueWorkItemOpSize = 15;

VOID (NTAPI *OriginalExQueueWorkItem)(
	PWORK_QUEUE_ITEM WorkItem,
	WORK_QUEUE_TYPE QueueType
);

UINT32 i = 0;

VOID NTAPI HookedExQueueWorkItem(
	PWORK_QUEUE_ITEM WorkItem,
	WORK_QUEUE_TYPE QueueType
) {

	if (i % 337 == 0) {
		DbgPrintEx(0, 0, "ExQueueWorkItem i=%u", i);
	}
	i++;

	OriginalExQueueWorkItem(WorkItem, QueueType);
}

#pragma section(".tram", read, execute)
#pragma comment(linker, "/SECTION:.tram,RE")
__declspec(allocate(".tram"))
UCHAR Trampoline[64];

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT		DriverObject,
	_In_ PUNICODE_STRING	RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);

	UNICODE_STRING routineString = { 0 };
	RtlInitUnicodeString(&routineString, L"ExQueueWorkItem");
	
	void* ExQueueWorkItemPtr = MmGetSystemRoutineAddress(&routineString);
	if (!ExQueueWorkItemPtr) {
		DbgPrintEx(0, 0, "Wtf was happened??\n");
		return STATUS_UNSUCCESSFUL;
	}

	OriginalExQueueWorkItem = (VOID(NTAPI*)(PWORK_QUEUE_ITEM, WORK_QUEUE_TYPE))Trampoline;

	if (HookTrampoline(ExQueueWorkItemPtr, (PVOID)HookedExQueueWorkItem, (PVOID)Trampoline, ExQueueWorkItemOpSize)) {
		DbgPrintEx(0, 0, "DriverEntry called. hooked.\n");
		return STATUS_SUCCESS;
	}
	else {
		DbgPrintEx(0, 0, "DriverEntry called. hook failed.\n");
		return STATUS_UNSUCCESSFUL;
	}
}