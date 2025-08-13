/*
    Credits to : https://github.com/wavestone-cdt/EDRSandblast
*/

#include <Windows.h>
#include <shlwapi.h>
#include <dbghelp.h>
#include <stdio.h>
#include <windef.h>
#include <winhttp.h>
#include <assert.h>

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "DbgHelp.lib")

#include "sandblast.h"

// ***** CODE OF FileUtils.cpp ***** //

/*
* Dumps the full content of a single file into a newly allocated buffer
*/
PBYTE ReadFullFileW(LPCWSTR fileName) {
    HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    PBYTE fileContent = (PBYTE)malloc(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(fileContent);
        fileContent = NULL;
    }
    CloseHandle(hFile);
    return fileContent;
}


/*
* Checks is a file extists (and is not a directory)
*/
BOOL FileExistsW(LPCWSTR szPath)
{
    DWORD dwAttrib = GetFileAttributesW(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
BOOL FileExistsA(LPCSTR szPath)
{
    DWORD dwAttrib = GetFileAttributesA(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/*
* Dumps the content of a buffer into a new file
*/
BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize) {
    HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    BOOL res = WriteFile(hFile, fileContent, (DWORD)fileSize, NULL, NULL);
    CloseHandle(hFile);
    return res;
}

// ***** CODE OF HttpClient.cpp ***** //

BOOL HttpsDownloadFullFile(LPCWSTR domain, LPCWSTR uri, PBYTE* output, SIZE_T* output_size) {
    ///wprintf_or_not(L"Downloading https://%s%s...\n", domain, uri);
    // Get proxy configuration
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
    WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);
    BOOL proxySet = !(proxyConfig.fAutoDetect || proxyConfig.lpszAutoConfigUrl != NULL);
    DWORD proxyAccessType = proxySet ? ((proxyConfig.lpszProxy == NULL) ?
        WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_NAMED_PROXY) : WINHTTP_ACCESS_TYPE_NO_PROXY;
    LPCWSTR proxyName = proxySet ? proxyConfig.lpszProxy : WINHTTP_NO_PROXY_NAME;
    LPCWSTR proxyBypass = proxySet ? proxyConfig.lpszProxyBypass : WINHTTP_NO_PROXY_BYPASS;

    // Initialize HTTP session and request
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.0", proxyAccessType, proxyName, proxyBypass, 0);
    if (hSession == NULL) {
        printf("WinHttpOpen failed with error : 0x%x\n", GetLastError());
        return FALSE;
    }
    HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        printf("WinHttpConnect failed with error : 0x%x\n", GetLastError());
        return FALSE;
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", uri, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        return FALSE;
    }

    // Configure proxy manually
    if (!proxySet)
    {
        WINHTTP_AUTOPROXY_OPTIONS  autoProxyOptions;
        autoProxyOptions.dwFlags = proxyConfig.lpszAutoConfigUrl != NULL ? WINHTTP_AUTOPROXY_CONFIG_URL : WINHTTP_AUTOPROXY_AUTO_DETECT;
        autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        autoProxyOptions.fAutoLogonIfChallenged = TRUE;

        if (proxyConfig.lpszAutoConfigUrl != NULL)
            autoProxyOptions.lpszAutoConfigUrl = proxyConfig.lpszAutoConfigUrl;

        WCHAR szUrl[MAX_PATH] = { 0 };
        swprintf_s(szUrl, _countof(szUrl), L"https://%ws%ws", domain, uri);

        WINHTTP_PROXY_INFO proxyInfo;
        WinHttpGetProxyForUrl(
            hSession,
            szUrl,
            &autoProxyOptions,
            &proxyInfo);

        WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
        DWORD logonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_AUTOLOGON_POLICY, &logonPolicy, sizeof(logonPolicy));
    }

    // Perform request
    BOOL bRequestSent;
    do {
        bRequestSent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    } while (!bRequestSent && GetLastError() == ERROR_WINHTTP_RESEND_REQUEST);
    if (!bRequestSent) {
        return FALSE;
    }
    BOOL bResponseReceived = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResponseReceived) {
        return FALSE;
    }

    // Read response
    DWORD dwAvailableSize = 0;
    DWORD dwDownloadedSize = 0;
    SIZE_T allocatedSize = 4096;
    if (!WinHttpQueryDataAvailable(hRequest, &dwAvailableSize))
    {
        return FALSE;
    }
    *output = (PBYTE)malloc(allocatedSize);
    *output_size = 0;
    while (dwAvailableSize)
    {
        while (*output_size + dwAvailableSize > allocatedSize) {
            allocatedSize *= 2;
            PBYTE new_output = (PBYTE)realloc(*output, allocatedSize);
            if (new_output == NULL)
            {
                return FALSE;
            }
            *output = new_output;
        }
        if (!WinHttpReadData(hRequest, *output + *output_size, dwAvailableSize, &dwDownloadedSize))
        {
            return FALSE;
        }
        *output_size += dwDownloadedSize;

        WinHttpQueryDataAvailable(hRequest, &dwAvailableSize);
    }
    PBYTE new_output = (PBYTE)realloc(*output, *output_size);
    if (new_output == NULL)
    {
        return FALSE;
    }
    *output = new_output;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return TRUE;
}

// ***** CODE OF PdbParser.cpp ***** //

// Written from information found here: https://llvm.org/docs/PDB/index.html

typedef DWORD ulittle32_t;

typedef struct SuperBlock_t {
    char FileMagic[0x20];
    ulittle32_t BlockSize;
    ulittle32_t FreeBlockMapBlock;
    ulittle32_t NumBlocks;
    ulittle32_t NumDirectoryBytes;
    ulittle32_t Unknown;
    ulittle32_t BlockMapAddr;
}SuperBlock;


/*
struct StreamDirectory {
    ulittle32_t NumStreams;
    ulittle32_t StreamSizes[NumStreams];
    ulittle32_t StreamBlocks[NumStreams][];
};
*/

typedef struct PdbInfoStreamHeader_t {
    DWORD Version;
    DWORD Signature;
    DWORD Age;
    GUID UniqueId;
} PdbInfoStreamHeader;

PVOID extractGuidFromPdb(LPWSTR filepath) {
    GUID* guid = NULL;
    HANDLE hMapping = NULL;
    PBYTE filemap = NULL;
    DWORD* StreamDirectory = NULL;
    DWORD** StreamBlocks = NULL;
    DWORD NumStreams = 0;

    HANDLE hFile = CreateFileW(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        if (StreamBlocks) {
            for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
                if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                    free(StreamBlocks[stream_i]);
                }
            }
            free(StreamBlocks);
        }
        if (StreamDirectory) {
            free(StreamDirectory);
        }
        if (filemap) {
            UnmapViewOfFile(filemap);
        }
        if (hMapping != NULL) {
            CloseHandle(hMapping);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }
    filemap = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (filemap == NULL) {
        if (StreamBlocks) {
            for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
                if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                    free(StreamBlocks[stream_i]);
                }
            }
            free(StreamBlocks);
        }
        if (StreamDirectory) {
            free(StreamDirectory);
        }
        if (filemap) {
            UnmapViewOfFile(filemap);
        }
        if (hMapping != NULL) {
            CloseHandle(hMapping);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }
    SuperBlock* superblock = (SuperBlock*)filemap;
    DWORD blockSize = superblock->BlockSize;
    DWORD* StreamDirectoryBlockMap = (DWORD*)(filemap + (ULONG_PTR)superblock->BlockMapAddr * blockSize);
    StreamDirectory = (DWORD*)calloc(superblock->NumDirectoryBytes, 1);
    if (StreamDirectory == NULL) {
        if (StreamBlocks) {
            for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
                if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                    free(StreamBlocks[stream_i]);
                }
            }
            free(StreamBlocks);
        }
        if (StreamDirectory) {
            free(StreamDirectory);
        }
        if (filemap) {
            UnmapViewOfFile(filemap);
        }
        if (hMapping != NULL) {
            CloseHandle(hMapping);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }
    DWORD StreamDirectoryBlockIndex = 0;
    DWORD StreamDirectoryRemainingSize = superblock->NumDirectoryBytes;
    while (StreamDirectoryRemainingSize) {
        DWORD SizeToCopy = min(StreamDirectoryRemainingSize, blockSize);
        memcpy(
            ((PBYTE)StreamDirectory) + (ULONG_PTR)StreamDirectoryBlockIndex * blockSize,
            ((PBYTE)filemap) + (ULONG_PTR)blockSize * StreamDirectoryBlockMap[StreamDirectoryBlockIndex],
            SizeToCopy);
        StreamDirectoryBlockIndex++;
        StreamDirectoryRemainingSize -= SizeToCopy;
    }
    NumStreams = StreamDirectory[0];
    if (NumStreams < 2) {
        NumStreams = 0;
        if (StreamBlocks) {
            for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
                if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                    free(StreamBlocks[stream_i]);
                }
            }
            free(StreamBlocks);
        }
        if (StreamDirectory) {
            free(StreamDirectory);
        }
        if (filemap) {
            UnmapViewOfFile(filemap);
        }
        if (hMapping != NULL) {
            CloseHandle(hMapping);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }
    StreamBlocks = (DWORD**)calloc(NumStreams, sizeof(DWORD*));
    if (StreamBlocks == NULL) {
        if (StreamBlocks) {
            for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
                if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                    free(StreamBlocks[stream_i]);
                }
            }
            free(StreamBlocks);
        }
        if (StreamDirectory) {
            free(StreamDirectory);
        }
        if (filemap) {
            UnmapViewOfFile(filemap);
        }
        if (hMapping != NULL) {
            CloseHandle(hMapping);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }
    DWORD* StreamBlocksFlat = &StreamDirectory[1 + NumStreams];
    DWORD i = 0;
    if ((1 + NumStreams) >= superblock->NumDirectoryBytes / 4) {
        if (StreamBlocks) {
            for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
                if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                    free(StreamBlocks[stream_i]);
                }
            }
            free(StreamBlocks);
        }
        if (StreamDirectory) {
            free(StreamDirectory);
        }
        if (filemap) {
            UnmapViewOfFile(filemap);
        }
        if (hMapping != NULL) {
            CloseHandle(hMapping);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }
    for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
        DWORD StreamSize = StreamDirectory[1 + stream_i];
        DWORD StreamBlockCount = 0;
        while (StreamBlockCount * blockSize < StreamSize) {
            PVOID tmp = realloc(StreamBlocks[stream_i], ((SIZE_T)StreamBlockCount + 1) * sizeof(DWORD));
            if (tmp == NULL) {
                if (StreamBlocks) {
                    for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
                        if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                            free(StreamBlocks[stream_i]);
                        }
                    }
                    free(StreamBlocks);
                }
                if (StreamDirectory) {
                    free(StreamDirectory);
                }
                if (filemap) {
                    UnmapViewOfFile(filemap);
                }
                if (hMapping != NULL) {
                    CloseHandle(hMapping);
                }
                if (hFile != INVALID_HANDLE_VALUE) {
                    CloseHandle(hFile);
                }
            }
            StreamBlocks[stream_i] = (DWORD*)tmp;
            StreamBlocks[stream_i][StreamBlockCount] = StreamBlocksFlat[i];
            i++;
            StreamBlockCount++;
        }
    }
    DWORD PdbInfoStreamSize = StreamDirectory[1 + 1];
    if (PdbInfoStreamSize == 0) {
        if (StreamBlocks) {
            for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
                if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                    free(StreamBlocks[stream_i]);
                }
            }
            free(StreamBlocks);
        }
        if (StreamDirectory) {
            free(StreamDirectory);
        }
        if (filemap) {
            UnmapViewOfFile(filemap);
        }
        if (hMapping != NULL) {
            CloseHandle(hMapping);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }
    PdbInfoStreamHeader* PdbInfoStream = (PdbInfoStreamHeader*)(filemap + (ULONG_PTR)StreamBlocks[1][0] * blockSize);
    guid = (GUID*)calloc(1, sizeof(GUID));
    if (guid == NULL) {
        if (StreamBlocks) {
            for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
                if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                    free(StreamBlocks[stream_i]);
                }
            }
            free(StreamBlocks);
        }
        if (StreamDirectory) {
            free(StreamDirectory);
        }
        if (filemap) {
            UnmapViewOfFile(filemap);
        }
        if (hMapping != NULL) {
            CloseHandle(hMapping);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }
    memcpy(guid, &PdbInfoStream->UniqueId, sizeof(GUID));


    return guid;
}

// ***** CODE OF pdbSymbols.cpp ***** //

BOOL DownloadPDB(GUID guid, DWORD age, LPCWSTR pdb_name_w, PBYTE* file, SIZE_T* file_size) {
	WCHAR full_pdb_uri[MAX_PATH] = { 0 };
	swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%04hX%04hX%016llX%X/%s", pdb_name_w, guid.Data1, guid.Data2, guid.Data3, _byteswap_uint64(*((DWORD64*)guid.Data4)), age, pdb_name_w);
	return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadPDBFromPE(PE* image_pe, PBYTE* file, SIZE_T* file_size) {
	WCHAR pdb_name_w[MAX_PATH] = { 0 };
	GUID guid = image_pe->codeviewDebugInfo->guid;
	DWORD age = image_pe->codeviewDebugInfo->age;
	MultiByteToWideChar(CP_UTF8, 0, image_pe->codeviewDebugInfo->pdbName, -1, pdb_name_w, _countof(pdb_name_w));
	return DownloadPDB(guid, age, pdb_name_w, file, file_size);
}

BOOL DownloadOriginalFileW(DWORD image_timestamp, DWORD image_size, LPCWSTR image_name, PBYTE* file, SIZE_T* file_size) {
	WCHAR full_pdb_uri[MAX_PATH] = { 0 };
	swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%X/%s", image_name, image_timestamp, image_size, image_name);
	return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadOriginalFileFromPE(PE* image_pe, _In_opt_ LPCWSTR image_name, PBYTE* file, SIZE_T* file_size) {
	DWORD image_size = image_pe->optHeader->SizeOfImage;
	//useless check
	if (image_size & 0xFFF) {
		image_size &= ~0xFFF;
		image_size += 0x1000;
	}
	DWORD image_timestamp = image_pe->ntHeader->FileHeader.TimeDateStamp;
	WCHAR image_name_w[MAX_PATH] = { 0 };
	if (image_name == NULL) {
		if (image_pe->exportDirectory != NULL) {
			LPCSTR image_name_a = (LPCSTR)PE_RVA_to_Addr(image_pe, image_pe->exportDirectory->Name);
			MultiByteToWideChar(CP_UTF8, 0, image_name_a, -1, image_name_w, _countof(image_name_w));
			image_name = image_name_w;
		}
		else {
			return FALSE;
		}
	}
	return DownloadOriginalFileW(image_timestamp, image_size, image_name, file, file_size);
}


symbol_ctx* LoadSymbolsFromPE(PE* pe) {
	symbol_ctx* ctx = (symbol_ctx*)calloc(1, sizeof(symbol_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	if (strchr(pe->codeviewDebugInfo->pdbName, '\\')) {
		// path is strange, PDB file won't be found on Microsoft Symbol Server, better give up...
		return NULL;
	}
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, NULL, 0);
	ctx->pdb_name_w = (LPWSTR)calloc(size_needed, sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, ctx->pdb_name_w, size_needed);
	BOOL needPdbDownload = FALSE;
	if (!FileExistsW(ctx->pdb_name_w)) {
		needPdbDownload = TRUE;
	}
	else {
		// PDB file exists, but is it the right version ?
		GUID* guid = (GUID*)extractGuidFromPdb(ctx->pdb_name_w);
		if (!guid || memcmp(guid, &pe->codeviewDebugInfo->guid, sizeof(GUID))) {
			needPdbDownload = TRUE;
		}
		free(guid);
	}
	if (needPdbDownload) {
		PBYTE file;
		SIZE_T file_size;
		BOOL res = DownloadPDBFromPE(pe, &file, &file_size);
		if (!res) {
			free(ctx);
			return NULL;
		}
		WriteFullFileW(ctx->pdb_name_w, file, file_size);
		free(file);
	}
	DWORD64 asked_pdb_base_addr = 0x1337000;
	DWORD pdb_image_size = MAXDWORD;
	HANDLE cp = GetCurrentProcess();
	if (!SymInitialize(cp, NULL, FALSE)) {
		free(ctx);
		return NULL;
	}
	ctx->sym_handle = cp;

	DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	while (pdb_base_addr == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_SUCCESS)
			break;
		if (err == ERROR_FILE_NOT_FOUND) {
			printf("PDB file not found\n");
			SymUnloadModule(cp, asked_pdb_base_addr);//TODO : fix handle leak
			SymCleanup(cp);
			free(ctx);
			return NULL;
		}
		printf("SymLoadModuleExW, error 0x%x\n", GetLastError());
		asked_pdb_base_addr += 0x1000000;
		pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	}
	ctx->pdb_base_addr = pdb_base_addr;
	return ctx;
}

symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path) {
	PVOID image_content = ReadFullFileW(image_file_path);
	PE* pe = PE_create(image_content, FALSE);
	symbol_ctx* ctx = LoadSymbolsFromPE(pe);
	PE_destroy(pe);
	free(image_content);
	return ctx;
}

DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, symbol_name, &si.si);
	if (res) {
		return si.si.Address - ctx->pdb_base_addr;
	}
	else {
		return 0;
	}
}

DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si);
	if (!res) {
		return 0;
	}

	TI_FINDCHILDREN_PARAMS* childrenParam = (TI_FINDCHILDREN_PARAMS*)calloc(1, sizeof(TI_FINDCHILDREN_PARAMS));
	if (childrenParam == NULL) {
		return 0;
	}

	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, &childrenParam->Count);
	if (!res) {
		return 0;
	}
	TI_FINDCHILDREN_PARAMS* ptr = (TI_FINDCHILDREN_PARAMS*)realloc(childrenParam, sizeof(TI_FINDCHILDREN_PARAMS) + childrenParam->Count * sizeof(ULONG));
	if (ptr == NULL) {
		free(childrenParam);
		return 0;
	}
	childrenParam = ptr;
	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_FINDCHILDREN, childrenParam);
	DWORD offset = 0;
	for (ULONG i = 0; i < childrenParam->Count; i++) {
		ULONG childID = childrenParam->ChildId[i];
		WCHAR* name = NULL;
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_SYMNAME, &name);
		if (wcscmp(field_name, name)) {
			continue;
		}
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_OFFSET, &offset);
		break;
	}
	free(childrenParam);
	return offset;
}

void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb) {
	SymUnloadModule(ctx->sym_handle, ctx->pdb_base_addr);
	SymCleanup(ctx->sym_handle);
	if (delete_pdb) {
		DeleteFileW(ctx->pdb_name_w);
	}
	free(ctx->pdb_name_w);
	ctx->pdb_name_w = NULL;
	free(ctx);
}

// ***** CODE OF PEParser.cpp ***** //

IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva) {
    IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
    for (DWORD sectionIndex = 0; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
        DWORD currSectionVA = sectionHeaders[sectionIndex].VirtualAddress;
        DWORD currSectionVSize = sectionHeaders[sectionIndex].Misc.VirtualSize;
        if (currSectionVA <= rva && rva < currSectionVA + currSectionVSize) {
            return &sectionHeaders[sectionIndex];
        }
    }
    return NULL;
}

/*
Get the next section header having the given memory access permissions, after the provided section headers "prev".
Exemple : PE_nextSectionHeader_fromPermissions(pe, textSection, 1, -1, 0) returns the first section header in the list after "textSection" that is readable and not writable.
Returns NULL if no section header is found.
*/
IMAGE_SECTION_HEADER* PE_nextSectionHeader_fromPermissions(PE* pe, IMAGE_SECTION_HEADER* prev, INT8 readable, INT8 writable, INT8 executable) {
    IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
    DWORD firstSectionIndex = prev == NULL ? 0 : (DWORD)((prev + 1) - sectionHeaders);
    for (DWORD sectionIndex = firstSectionIndex; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
        DWORD sectionCharacteristics = sectionHeaders[sectionIndex].Characteristics;
        if (readable != 0) {
            if (sectionCharacteristics & IMAGE_SCN_MEM_READ) {
                if (readable == -1) {
                    continue;
                }
            }
            else {
                if (readable == 1) {
                    continue;
                }
            }
        }
        if (writable != 0) {
            if (sectionCharacteristics & IMAGE_SCN_MEM_WRITE) {
                if (writable == -1) {
                    continue;
                }
            }
            else {
                if (writable == 1) {
                    continue;
                }
            }
        }
        if (executable != 0) {
            if (sectionCharacteristics & IMAGE_SCN_MEM_EXECUTE) {
                if (executable == -1) {
                    continue;
                }
            }
            else {
                if (executable == 1) {
                    continue;
                }
            }
        }
        return &sectionHeaders[sectionIndex];
    }
    return NULL;
}


PVOID PE_RVA_to_Addr(PE* pe, DWORD rva) {
    PVOID peBase = pe->dosHeader;
    if (pe->isMemoryMapped) {
        return (PBYTE)peBase + rva;
    }

    IMAGE_SECTION_HEADER* rvaSectionHeader = PE_sectionHeader_fromRVA(pe, rva);
    if (NULL == rvaSectionHeader) {
        return NULL;
    }
    else {
        return (PBYTE)peBase + rvaSectionHeader->PointerToRawData + (rva - rvaSectionHeader->VirtualAddress);
    }
}

DWORD PE_Addr_to_RVA(PE* pe, PVOID addr) {
    for (int i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD sectionVA = pe->sectionHeaders[i].VirtualAddress;
        DWORD sectionSize = pe->sectionHeaders[i].Misc.VirtualSize;
        PVOID sectionAddr = PE_RVA_to_Addr(pe, sectionVA);
        if (sectionAddr <= addr && addr < (PVOID)((intptr_t)sectionAddr + (intptr_t)sectionSize)) {
            intptr_t relativeOffset = ((intptr_t)addr - (intptr_t)sectionAddr);
            assert(relativeOffset <= MAXDWORD);
            return sectionVA + (DWORD)relativeOffset;
        }
    }
    return 0;
}


VOID PE_parseRelocations(PE* pe) {
    IMAGE_BASE_RELOCATION* relocationBlocks = (IMAGE_BASE_RELOCATION*)PE_RVA_to_Addr(pe, pe->dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    IMAGE_BASE_RELOCATION* relocationBlockPtr = relocationBlocks;
    IMAGE_BASE_RELOCATION* nextRelocationBlockPtr;
    pe->nbRelocations = 0;
    DWORD relocationsLength = 16;
    pe->relocations = (PE_relocation*)calloc(relocationsLength, sizeof(PE_relocation));
    if (NULL == pe->relocations)
        exit(1);

    while (((size_t)relocationBlockPtr - (size_t)relocationBlocks) < pe->dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        IMAGE_RELOCATION_ENTRY* relocationEntry = (IMAGE_RELOCATION_ENTRY*)&relocationBlockPtr[1];
        nextRelocationBlockPtr = (IMAGE_BASE_RELOCATION*)(((PBYTE)relocationBlockPtr) + relocationBlockPtr->SizeOfBlock);
        while ((PBYTE)relocationEntry < (PBYTE)nextRelocationBlockPtr) {
            DWORD relocationRVA = relocationBlockPtr->VirtualAddress + relocationEntry->Offset;
            if (pe->nbRelocations >= relocationsLength) {
                relocationsLength *= 2;
                void* pe_relocations = pe->relocations;
                assert(NULL != pe_relocations);
                pe->relocations = (PE_relocation*)realloc(pe_relocations, relocationsLength * sizeof(PE_relocation));
                assert(NULL != pe->relocations);
            }
            pe->relocations[pe->nbRelocations].RVA = relocationRVA;
            pe->relocations[pe->nbRelocations].Type = relocationEntry->Type;
            pe->nbRelocations++;
            relocationEntry++;
        }
        relocationBlockPtr = nextRelocationBlockPtr;
    }
    void* pe_relocations = pe->relocations;
    assert(pe_relocations != NULL);
    pe->relocations = (PE_relocation*)realloc(pe_relocations, pe->nbRelocations * sizeof(PE_relocation));
    if (NULL == pe->relocations)
        exit(1);
}

VOID PE_rebasePE(PE* pe, LPVOID newBaseAddress)
{
    DWORD* relocDwAddress;
    QWORD* relocQwAddress;

    if (pe->isMemoryMapped) {
        printf("ERROR : Cannot rebase PE that is memory mapped (LoadLibrary'd)\n");
        return;
    }
    if (NULL == pe->relocations) {
        PE_parseRelocations(pe);
    }
    assert(pe->relocations != NULL);
    PVOID oldBaseAddress = pe->baseAddress;
    pe->baseAddress = newBaseAddress;
    intptr_t relativeOffset = ((intptr_t)newBaseAddress) - ((intptr_t)oldBaseAddress);
    for (DWORD i = 0; i < pe->nbRelocations; i++) {
        switch (pe->relocations[i].Type) {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            relocDwAddress = (DWORD*)PE_RVA_to_Addr(pe, pe->relocations[i].RVA);
            assert(relativeOffset <= MAXDWORD);
            *relocDwAddress += (DWORD)relativeOffset;
            break;
        case IMAGE_REL_BASED_DIR64:
            relocQwAddress = (QWORD*)PE_RVA_to_Addr(pe, pe->relocations[i].RVA);
            *relocQwAddress += (QWORD)relativeOffset;
            break;
        default:
            printf("Unsupported relocation : 0x%x\nExiting...\n", pe->relocations[i].Type);
            exit(1);
        }
    }
    return;
}

VOID PE_read(PE* pe, LPCVOID address, SIZE_T size, PVOID buffer) {
    if (pe->isInAnotherAddressSpace) {
        ReadProcessMemory(pe->hProcess, address, buffer, size, NULL);
    }
    else if (pe->isInKernelLand) {
        pe->kernel_read((DWORD64)address, buffer, size);
    }
    else {
        memcpy(buffer, address, size);
    }
}

#define PE_ReadMemoryType(TYPE) \
TYPE PE_ ## TYPE ## (PE* pe, LPCVOID address) {\
    TYPE res;\
    PE_read(pe, address, sizeof(TYPE), &res);\
    return res;\
}
PE_ReadMemoryType(BYTE);
PE_ReadMemoryType(WORD);
PE_ReadMemoryType(DWORD);
PE_ReadMemoryType(DWORD64);

#define PE_ArrayType(TYPE) \
TYPE PE_ ## TYPE ## _Array(PE* pe, PVOID address, SIZE_T index) {\
    return PE_ ## TYPE ## (pe, (PVOID)(((intptr_t)address)+index*sizeof(TYPE)));\
}
PE_ArrayType(BYTE);
PE_ArrayType(WORD);
PE_ArrayType(DWORD);
PE_ArrayType(DWORD64);

LPCSTR PE_STR(PE* pe, LPCSTR address) {
    if (pe->isInAnotherAddressSpace || pe->isInKernelLand) {
        SIZE_T slen = 16;
        LPSTR s = (LPSTR)calloc(slen, 1);
        if (s == NULL) {
            exit(1);
        }
        SIZE_T i = 0;
        do {
            if (slen <= i) {
                slen *= 2;
                LPSTR tmp = (LPSTR)realloc(s, slen);
                if (NULL == tmp) {
                    exit(1);
                }
                s = tmp;
            }
            s[i] = PE_BYTE(pe, address + i);
            i++;
        } while (s[i - 1] != '\0');
        return s;
    }
    else {
        return address;
    }
}

VOID PE_STR_free(PE* pe, LPCSTR s) {
    if (pe->isInAnotherAddressSpace || pe->isInKernelLand) {
        free((PVOID)s);
    }
}


PE* _PE_create_common(PVOID imageBase, BOOL isMemoryMapped, BOOL isInAnotherAddressSpace, HANDLE hProcess, BOOL isInKernelLand, kernel_read_memory_func ReadPrimitive);

PE* PE_create_from_another_address_space(HANDLE hProcess, PVOID imageBase) {
    return _PE_create_common(imageBase, TRUE, TRUE, hProcess, FALSE, NULL);
}

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped) {
    return _PE_create_common(imageBase, isMemoryMapped, FALSE, INVALID_HANDLE_VALUE, FALSE, NULL);
}

PE* PE_create_from_kernel(PVOID imageBase, kernel_read_memory_func ReadPrimitive) {
    return _PE_create_common(imageBase, TRUE, FALSE, INVALID_HANDLE_VALUE, TRUE, ReadPrimitive);
}


PE* _PE_create_common(PVOID imageBase, BOOL isMemoryMapped, BOOL isInAnotherAddressSpace, HANDLE hProcess, BOOL isInKernelLand, kernel_read_memory_func ReadPrimitive) {
    PE* pe = (PE*)calloc(1, sizeof(PE));
    if (NULL == pe) {
        exit(1);
    }
    pe->isMemoryMapped = isMemoryMapped;
    pe->hProcess = hProcess;
    pe->isInAnotherAddressSpace = isInAnotherAddressSpace;
    pe->isInKernelLand = isInKernelLand;
    pe->kernel_read = ReadPrimitive;
    pe->baseAddress = imageBase;
    pe->dosHeader = (IMAGE_DOS_HEADER*)imageBase;
    DWORD ntHeaderPtrAddress = PE_DWORD(pe, &((IMAGE_DOS_HEADER*)imageBase)->e_lfanew);
    pe->ntHeader = (IMAGE_NT_HEADERS*)((intptr_t)pe->baseAddress + ntHeaderPtrAddress);
    pe->optHeader = (IMAGE_OPTIONAL_HEADER*)(&pe->ntHeader->OptionalHeader);
    pe->dataDir = pe->optHeader->DataDirectory;
    WORD sizeOfOptionnalHeader = PE_WORD(pe, &pe->ntHeader->FileHeader.SizeOfOptionalHeader);
    pe->sectionHeaders = (IMAGE_SECTION_HEADER*)((intptr_t)pe->optHeader + sizeOfOptionnalHeader);
    DWORD exportRVA = PE_DWORD(pe, &pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (exportRVA == 0) {
        pe->exportDirectory = NULL;
        pe->exportedNames = NULL;
        pe->exportedFunctions = NULL;
        pe->exportedOrdinals = NULL;
    }
    else {
        pe->exportDirectory = (IMAGE_EXPORT_DIRECTORY*)PE_RVA_to_Addr(pe, exportRVA);

        DWORD AddressOfNames = PE_DWORD(pe, &pe->exportDirectory->AddressOfNames);
        pe->exportedNames = (LPDWORD)PE_RVA_to_Addr(pe, AddressOfNames);

        DWORD AddressOfFunctions = PE_DWORD(pe, &pe->exportDirectory->AddressOfFunctions);
        pe->exportedFunctions = (LPDWORD)PE_RVA_to_Addr(pe, AddressOfFunctions);

        DWORD AddressOfNameOrdinals = PE_DWORD(pe, &pe->exportDirectory->AddressOfNameOrdinals);
        pe->exportedOrdinals = (LPWORD)PE_RVA_to_Addr(pe, AddressOfNameOrdinals);

        pe->exportedNamesLength = PE_DWORD(pe, &pe->exportDirectory->NumberOfNames);
    }
    pe->relocations = NULL;
    DWORD debugRVA = PE_DWORD(pe, &pe->dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
    if (debugRVA == 0) {
        pe->debugDirectory = NULL;
    }
    else {
        pe->debugDirectory = (IMAGE_DEBUG_DIRECTORY*)PE_RVA_to_Addr(pe, debugRVA);
        DWORD debugDirectoryType = PE_DWORD(pe, &pe->debugDirectory->Type);
        if (debugDirectoryType != IMAGE_DEBUG_TYPE_CODEVIEW) {
            pe->debugDirectory = NULL;
        }
        else {
            DWORD debugDirectoryAddressOfRawData = PE_DWORD(pe, &pe->debugDirectory->AddressOfRawData);
            pe->codeviewDebugInfo = (PE_codeview_debug_info*)PE_RVA_to_Addr(pe, debugDirectoryAddressOfRawData);
            DWORD codeviewDebugInfoSignature = PE_DWORD(pe, &pe->codeviewDebugInfo->signature);
            if (codeviewDebugInfoSignature != *((DWORD*)"RSDS")) {
                pe->debugDirectory = NULL;
                pe->codeviewDebugInfo = NULL;
            }
        }
    }
    return pe;
}

//TODO : implement the case where the PE is in another address space
DWORD PE_functionRVA(PE* pe, LPCSTR functionName) {
    IMAGE_EXPORT_DIRECTORY* exportDirectory = pe->exportDirectory;
    LPDWORD exportedNames = pe->exportedNames;
    LPDWORD exportedFunctions = pe->exportedFunctions;
    LPWORD exportedNameOrdinals = pe->exportedOrdinals;

    DWORD nameOrdinal_low = 0;
    LPCSTR exportName_low = (LPCSTR)PE_RVA_to_Addr(pe, PE_DWORD_Array(pe, exportedNames, nameOrdinal_low));
    exportName_low = PE_STR(pe, exportName_low);
    DWORD nameOrdinal_high = PE_DWORD(pe, &exportDirectory->NumberOfNames);
    DWORD nameOrdinal_mid;
    LPCSTR exportName_mid = NULL;

    while (nameOrdinal_high - nameOrdinal_low > 1) {
        nameOrdinal_mid = (nameOrdinal_high + nameOrdinal_low) / 2;
        if (exportName_mid) {
            PE_STR_free(pe, exportName_mid);
        }
        exportName_mid = (LPCSTR)PE_RVA_to_Addr(pe, PE_DWORD_Array(pe, exportedNames, nameOrdinal_mid));
        exportName_mid = PE_STR(pe, exportName_mid);

        if (strcmp(exportName_mid, functionName) > 0) {
            nameOrdinal_high = nameOrdinal_mid;
        }
        else {
            nameOrdinal_low = nameOrdinal_mid;
            PE_STR_free(pe, exportName_low);
            exportName_low = exportName_mid;
            exportName_mid = NULL;
        }
    }
    if (exportName_mid) {
        PE_STR_free(pe, exportName_mid);
    }
    if (!strcmp(exportName_low, functionName)) {
        PE_STR_free(pe, exportName_low);
        return PE_DWORD_Array(pe, exportedFunctions, PE_WORD_Array(pe, exportedNameOrdinals, nameOrdinal_low));
    }
    return 0;
}

PVOID PE_functionAddr(PE* pe, LPCSTR functionName) {
    DWORD functionRVA = PE_functionRVA(pe, functionName);
    if (functionRVA == 0) {
        return NULL;
    }
    return PE_RVA_to_Addr(pe, functionRVA);
}

PVOID PE_search_pattern(PE* pe, PBYTE pattern, size_t patternSize) {
    for (int i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD sectionVA = pe->sectionHeaders[i].VirtualAddress;
        DWORD sectionSize = pe->sectionHeaders[i].Misc.VirtualSize;
        if ((size_t)sectionSize < patternSize) {
            continue;
        }
        assert(patternSize <= MAXDWORD);
        DWORD endSize = sectionSize - (DWORD)patternSize;
        for (DWORD offset = 0; offset < endSize; offset++) {
            PBYTE ptr = (PBYTE)PE_RVA_to_Addr(pe, sectionVA + offset);
            if (!memcmp(ptr, pattern, patternSize)) {
                return ptr;
            }
        }
    }
    return NULL;
}

/*
* Look for an instruction that references address targetRVA relatively from its own address, starting the search at fromRVA.
* Searches a 8, 16 or 32 bits relative displacement that points to targetRVA (on x86_84, 64-bits relative displacements do not exist)
* Returns the RVA of the reference (in the middle of the instruction)
*
* Example:
*
* PAGE:14084EA2B 45 33 FF                             xor     r15d, r15d
* PAGE:14084EA2E 4C 8D 2D [6B DA 49 00]               lea     r13, PspCreateProcessNotifyRoutine ; array at address 140CEC4A0
* PAGE:14084EA35 4E 8D 24 FD 00 00 00 00              lea     r12, ds:0[r15*8]
*
* At address 14084EA31 (14084EA2E+3), we find the DWORD 0x0049DA6B (see brackets), which is a displacement relative to the
* address of the next instruction (14084EA35). 0x0049DA6B + 0x14084EA35 being equal to 0x140CEC4A0, this is how the array
* PspCreateProcessNotifyRoutine is referenced by the lea instruction.
*/
DWORD PE_find_static_relative_reference(PE* pe, DWORD targetRVA, DWORD relativeReferenceSize, DWORD fromRVA) {
    QWORD startRVA;
    QWORD endRVA;

    switch (relativeReferenceSize)
    {
    case 1:
        startRVA = (QWORD)targetRVA - MAXINT8 - relativeReferenceSize;
        endRVA = (QWORD)targetRVA - MININT8 - relativeReferenceSize;
        break;
    case 2:
        startRVA = (QWORD)targetRVA - MAXINT16 - relativeReferenceSize;
        endRVA = (QWORD)targetRVA - MININT16 - relativeReferenceSize;
        break;
    case 4:
        startRVA = (QWORD)targetRVA - MAXINT32 - relativeReferenceSize;
        endRVA = (QWORD)targetRVA - MININT32 - relativeReferenceSize;
        break;
    default:
        return 0;
    }
    if (startRVA > targetRVA) {
        startRVA = 0;
    }
    if (startRVA < fromRVA) {
        startRVA = fromRVA;
    }
    if (endRVA > MAXDWORD) {
        endRVA = MAXDWORD;
    }
    for (int i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD startRVA_inSection = pe->sectionHeaders[i].VirtualAddress;
        startRVA_inSection = max(startRVA_inSection, (DWORD)startRVA);
        DWORD endRVA_inSection = startRVA_inSection + pe->sectionHeaders[i].Misc.VirtualSize - relativeReferenceSize;
        endRVA_inSection = min(endRVA_inSection, (DWORD)endRVA);
        for (DWORD rva = startRVA_inSection; rva <= endRVA_inSection; rva++) {
            switch (relativeReferenceSize) {
            case 1:
                if (rva + relativeReferenceSize + *(INT8*)PE_RVA_to_Addr(pe, rva) == targetRVA) {
                    return rva;
                }
                break;
            case 2:
                if (rva + relativeReferenceSize + *(INT16*)PE_RVA_to_Addr(pe, rva) == targetRVA) {
                    return rva;
                }
                break;
            case 4:
                if (rva + relativeReferenceSize + *(INT32*)PE_RVA_to_Addr(pe, rva) == targetRVA) {
                    return rva;
                }
                break;
            }
        }

    }
    return 0;
}

VOID PE_destroy(PE* pe)
{
    if (pe->relocations) {
        free(pe->relocations);
        pe->relocations = NULL;
    }
    free(pe);
}
