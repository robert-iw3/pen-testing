/*
 * @file Entry.cpp
 * @brief Entry Point.
 */

#include "Include.hpp"
#include "Module.hpp"
#include "Global.hpp"
#include "Log.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	
	
	if (!gl::RtVar::InitializeRuntimeVariables()) {
		LogError("DriverEntry: Failed to initialize runtime variables.");
		return STATUS_UNSUCCESSFUL;
	}

	LogVerbose("DriverEntry: Driver Image Base: %llX", gl::RtVar::Self::SelfBase);
	LogVerbose("DriverEntry: Driver Image Size: %llx", gl::RtVar::Self::SelfSize);

	if (!wsbp::BypassPatchGuard()) {
		LogError("DriverEntry: Failed to bypass PatchGuard");
		return STATUS_UNSUCCESSFUL;
	}
	
	

	return STATUS_SUCCESS;
}