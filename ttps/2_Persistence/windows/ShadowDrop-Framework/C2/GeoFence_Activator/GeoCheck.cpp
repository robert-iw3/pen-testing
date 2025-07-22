#include <Windows.h>
#include <wininet.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

bool IsGeoAllowed() {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return false;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, "https://ipapi.co/json/", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    char buffer[1024];
    DWORD bytesRead;
    std::string response;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer)-1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        response += buffer;
    }
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    
    try {
        auto j = json::parse(response);
        std::string country = j["country_code"];
        return country == "US" || country == "CA"; // allowed countries
    } catch (...) {
        return false;
    }
}

void EnableGeoFence() {
    if (!IsGeoAllowed()) {
        // trigger self-destruct if in blocked region
        BurnerProtocol::SelfDestruct();
    }
}
