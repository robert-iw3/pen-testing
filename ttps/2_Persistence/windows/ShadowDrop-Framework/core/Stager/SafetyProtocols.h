#pragma once
#include "../OperationalSecurity/EnvValidator.h"
#include "../AntiForensics/MemoryWiper.h"

class SafetyProtocols {
public:
    __declspec(noinline) static void PreExecutionCheck() {
        if (EnvValidator::IsDebuggerPresent() || 
            EnvValidator::IsInsideVM() || 
            !EnvValidator::IsAuthorizedDomain()) {
            
            TriggerSelfDestruct();
        }
    }

private:
    __declspec(noinline) static void TriggerSelfDestruct() {
        // destroy module in memory
        HMODULE hModule = GetModuleHandle(NULL);
        MODULEINFO modInfo;
        GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo));
        MemoryWiper::SecureErase(hModule, modInfo.SizeOfImage);
        
        // corrupt stack
        volatile int* p = nullptr;
        *p = 0xDEADBEEF;
    }
};
