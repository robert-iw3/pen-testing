#include "cryptor.h"
#include <Windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

__declspec(safebuffers) class KeyManager {
public:
    static BYTE* GetActiveKey() {
        BYTE key[32];
        SecureZeroMemory(key, sizeof(key));

        HCRYPTPROV hProv;
        CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

        HCRYPTKEY hKey;
        CryptImportKey(hProv, ENCRYPTED_KEY_BLOB, sizeof(ENCRYPTED_KEY_BLOB), 0, 0, &hKey);

        DWORD len = 32;
        CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, key, &len);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);

        return key;
    }

    static BYTE* GetNonce() {
        static BYTE nonce[12];
        BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        return nonce;
    }

private:
    static const BYTE ENCRYPTED_KEY_BLOB[48] = {
        // your key here - blob (AES-256)
    };
};
