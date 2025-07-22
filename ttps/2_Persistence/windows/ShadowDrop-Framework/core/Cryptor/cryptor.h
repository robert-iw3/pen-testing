#pragma once
#include <Windows.h>
#include <bcrypt.h>

class AESNI_Cryptor {
public:
    static BOOL Encrypt(BYTE* pData, DWORD dwDataLen, BYTE* key, DWORD keySize) {
        BCRYPT_ALG_HANDLE hAesAlg;
        BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        
        BCRYPT_KEY_HANDLE hKey;
        BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, key, keySize, 0);
        
        BYTE iv[12] = {0};
        BCryptEncrypt(hKey, pData, dwDataLen, NULL, iv, sizeof(iv), pData, dwDataLen, &dwDataLen, 0);
        
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return TRUE;
    }
};

class ChaCha20_Cryptor {
public:
    static VOID QuarterRound(ULONG& a, ULONG& b, ULONG& c, ULONG& d) {
        a += b; d ^= a; d = _rotl(d, 16);
        c += d; b ^= c; b = _rotl(b, 12);
        a += b; d ^= a; d = _rotl(d, 8);
        c += d; b ^= c; b = _rotl(b, 7);
    }

    static VOID Decrypt(BYTE* input, SIZE_T len, BYTE* key, BYTE* nonce, ULONG counter) {
        ULONG state[16];
        memcpy(state, "expand 32-byte k", 16);
        memcpy(state + 4, key, 32);
        state[12] = counter;
        memcpy(state + 13, nonce, 12);

        for (SIZE_T i = 0; i < len; i += 64) {
            ULONG workingState[16];
            memcpy(workingState, state, sizeof(workingState));

            for (int j = 0; j < 10; j++) {
                QuarterRound(workingState[0], workingState[4], workingState[8], workingState[12]);
                QuarterRound(workingState[1], workingState[5], workingState[9], workingState[13]);
                QuarterRound(workingState[2], workingState[6], workingState[10], workingState[14]);
                QuarterRound(workingState[3], workingState[7], workingState[11], workingState[15]);
                QuarterRound(workingState[0], workingState[5], workingState[10], workingState[15]);
                QuarterRound(workingState[1], workingState[6], workingState[11], workingState[12]);
                QuarterRound(workingState[2], workingState[7], workingState[8], workingState[13]);
                QuarterRound(workingState[3], workingState[4], workingState[9], workingState[14]);
            }

            // xor keystream
            for (int j = 0; j < 16; j++) workingState[j] += state[j];
            for (int j = 0; j < min(64, len - i); j++) {
                input[i + j] ^= ((BYTE*)workingState)[j];
            }

            if (++state[12] == 0) state[13]++;
        }
    }
};
