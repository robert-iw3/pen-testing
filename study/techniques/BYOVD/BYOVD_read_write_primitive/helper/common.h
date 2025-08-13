#pragma once

#include <Windows.h>
#include <stdio.h>

// ***** HELPER FUNCTIONS FOR STRING HASHING ***** //
// HASHA for A version of hashing and HASHW for W version of HASHING
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

// ***** HELPER FUNCTIONS ***** //
// Macros for printing
#define okay(msg, ...) printf("[+] "msg "\n", ##__VA_ARGS__);
#define info(msg, ...) printf("[i] "msg "\n", ##__VA_ARGS__);
#define error(msg, ...) printf("[-] "msg "\n", ##__VA_ARGS__);

#define okayW(msg, ...) wprintf(L"[+] " msg L"\n", ##__VA_ARGS__)
#define infoW(msg, ...) wprintf(L"[i] " msg L"\n", ##__VA_ARGS__)
#define errorW(msg, ...) wprintf(L"[-] " msg L"\n", ##__VA_ARGS__)

// Tabbed versions for info without the [i]
#define infoW_t(msg, ...) wprintf(L"\t" msg L"\n", ##__VA_ARGS__)
#define info_t(msg, ...) printf("\t"msg "\n", ##__VA_ARGS__);

// NT Macro for succes of syscalls
#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)

// ***** HELPER FUNCTION TO GET HANDLE TO CURRENT PROCESS ***** //
#define NtCurrentProcess() ((HANDLE)-1) // Return the pseudo handle for the current process

// ***** FUNCTION PROTOTYPES ***** //
// Function prototypes are needed so each source file is aware of the function's signature 
// (name, return type, and parameters) before the compiler encounters the function call.

// For functions in 'Helpers.c'
int errorWin32(const char* msg);
int errorNT(const char* msg, NTSTATUS ntstatus);
void print_bytes(IN void* ptr, IN int size);

// For functions in 'IO.c'
BOOL ReadPayloadFile(IN const char* FileInput, OUT PDWORD sPayloadSize, OUT unsigned char** pPayloadData);