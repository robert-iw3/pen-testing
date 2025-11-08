# SilentButDeadly

## Overview
SilentButDeadly is a network communication blocker specifically designed to neutralize EDR/AV software by preventing their cloud connectivity using Windows Filtering Platform (WFP). This version focuses solely on network isolation without process termination.

## Program Flow

### 1. **Initialization Phase**
```
[*] Checking administrative privileges...
[+] Running with Administrator privileges
[#] Press <Enter> to begin EDR enumeration...
```
- Verifies administrator privileges using `CheckTokenMembership()`
- Interactive prompts allow controlled execution

### 2. **EDR Discovery Phase**
```
[*] Scanning for target security processes...
[+] Found SentinelAgent.exe (SentinelOne) - PID: 1234
[+] Found MsMpEng.exe (Windows Defender) - PID: 5678
[*] Total target processes found: 2
[#] Press <Enter> to block network communications...
```
- Creates process snapshot using `CreateToolhelp32Snapshot()`
- Enumerates all running processes
- Matches against predefined EDR target list
- Opens process handles with `PROCESS_QUERY_INFORMATION` access

### 3. **WFP Initialization**
```
[*] Initializing Windows Filtering Platform...
[>] Initializing COM library
[>] Generating WFP provider GUID
[>] Opening WFP engine handle
[+] Windows Filtering Platform initialized successfully
```
- Initializes COM for GUID generation
- Creates dynamic WFP session (non-persistent by default)
- Establishes provider and sublayer with high priority (0x7FFF)

### 4. **Network Filter Implementation**
```
[*] Configuring network filters to block EDR communications...
[>] Processing filters for SentinelAgent.exe (PID: 1234)
[>] Process path: C:\Program Files\SentinelOne\Sentinel Agent\SentinelAgent.exe
[>] Outbound filter added successfully
[>] Inbound filter added successfully
[+] Network communication blocked for SentinelAgent.exe
[+] Communication blocking established for 2 processes
```

For each EDR process:
- Retrieves full process image path using `QueryFullProcessImageNameW()`
- Converts path to WFP AppID blob using `FwpmGetAppIdFromFileName0()`
- Creates two filters per process:
  - **Outbound Filter**: `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (blocks outgoing connections)
  - **Inbound Filter**: `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` (blocks incoming connections)

### 5. **Service Disruption Phase**
```
[*] Attempting to disable EDR services...
[>] Processing service: SentinelAgent
[>] Current service state: Running
[>] Attempting to stop service...
[+] Stop signal sent to SentinelAgent
[+] Service stopped successfully
[+] Service SentinelAgent set to disabled
[+] Disabled 2 EDR services
```
- Opens Service Control Manager
- For each EDR service:
  - Attempts graceful service stop
  - Changes startup type to `SERVICE_DISABLED`
  - Prevents automatic restart

### 6. **Summary Display**
```
=================================================================
                         OPERATION SUMMARY
=================================================================
  [SentinelOne] SentinelAgent.exe - PID: 1234
  [Windows Defender] MsMpEng.exe - PID: 5678

  Total Processes Found:    2
  Network Blocks Applied:   2
  WFP Status:               Active
=================================================================
[#] Press <Enter> to remove filters and exit...
```

### 7. **Cleanup Phase**
```
[*] Removing network blocking rules...
[+] Network blocking rules removed
[*] Operation complete
```
- Removes WFP provider (cascades to all filters)
- Closes WFP engine handle
- Releases COM resources
- Closes all process handles

## Key Technical Details

### WFP Filter Specifications
- **Layer**: Application Layer Enforcement (ALE)
- **Weight**: 0x7FFF (high priority)
- **Action**: `FWP_ACTION_BLOCK`
- **Condition**: `FWPM_CONDITION_ALE_APP_ID` (process-specific)
- **Flags**: `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`

### Supported EDR Targets
- SentinelOne (all components)
- Windows Defender
- Windows Defender ATP (MsSense.exe)
- Easily extensible via `g_EDRTargets` array

### Command Line Options
- `-v, --verbose`: Enable detailed operation logging
- `-p, --persistent`: Keep filters active after program exit
- `-h, --help`: Display usage information

### Error Handling
- Comprehensive error checking at each stage
- Graceful fallback on partial failures
- Detailed error codes for troubleshooting

### Security Considerations
- Requires Administrator privileges
- Non-persistent filters by default (cleared on exit)
- No driver loading or kernel manipulation
- Uses legitimate Windows APIs only

## Operational Impact

### Network Isolation Effects
1. EDR cannot receive cloud updates
2. Telemetry upload blocked
3. Remote management disabled
4. Real-time threat intelligence severed

### Service Disruption Effects
1. Prevents automatic restart
2. Disables scheduled scans
3. Stops background monitoring
4. Halts update mechanisms

### Detection Vectors
- WFP filter creation events
- Service stop/disable events
- Process handle access patterns
- No persistent artifacts (unless `-p` flag used)

## Usage Scenarios
1. **Pre-engagement Testing**: Verify EDR bypass before operation
2. **Controlled Environment**: Isolate EDR for malware analysis
3. **Red Team Operations**: Initial foothold establishment
4. **Security Research**: EDR behavior analysis

## Limitations
- IPv4 only (IPv6 requires additional layers)
- Requires active EDR processes (not effective if stopped)
- Some EDRs may have kernel-level network drivers
- Windows Firewall must be enabled for WFP to function
