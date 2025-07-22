#include <Windows.h>
#include <evntprov.h>
#include <time.h>

void LogForger::CreateDecoyLogs() {
    // generate fake security logs
    for (int i = 0; i < 50; i++) {
        std::string log = "User login successful: " + GenerateRandomUsername();
        LogForger::WriteEventLog(L"Security", log.c_str());
    }
}

std::string LogForger::GenerateRandomUsername() {
    const char* prefixes[] = {"john", "jane", "mike", "sarah", "admin"};
    const char* suffixes[] = {"doe", "smith", "jones", "lee", "admin"};
    
    return std::string(prefixes[rand() % 5]) + "." + 
           std::string(suffixes[rand() % 5]) + 
           std::to_string(rand() % 1000);
}

void LogForger::WriteEventLog(LPCWSTR source, LPCSTR message) {
    HANDLE hEventLog = RegisterEventSourceW(NULL, source);
    if (hEventLog) {
        const char* strings[] = {message};
        ReportEventA(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventLog);
    }
}
