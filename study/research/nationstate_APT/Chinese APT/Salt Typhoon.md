# Salt Typhoon – 2024-11 – Associated Tactics, Techniques and Procedures (TTPs)

Salt Typhoon, also known as FamousSparrow, GhostEmperor, Earth Estries, and UNC2286, is a Chinese Advanced Persistent Threat (APT) group that has been active since at least 2019. It primarily targets critical sectors, including Telecommunications and Government entities across the United States, the Asia-Pacific region, the Middle East, and South Africa. Since 2020, it has engaged in prolonged espionage campaigns against Governments and Internet Service Providers (ISPs), and by 2022, it expanded its focus to service providers supporting Government and Telecommunication organizations.

Salt Typhoon operates with high-level resources, advanced cyberespionage capabilities, and extensive experience in illicit activities. It employs multiple backdoors and hacking tools to maintain persistent access while minimizing detection. A key tactic involves PowerShell downgrade attacks to bypass Windows Antimalware Scan Interface (AMSI) logging. Additionally, public cloud and communication services such as GitHub, Gmail, AnonFiles, and File.io are leveraged to covertly exchange commands and exfiltrate stolen data.

The group has been observed exploiting Microsoft Exchange’s ProxyLogon vulnerabilities, a pre-authenticated Remote Code Execution (RCE) exploit chain that allows attackers to take over any reachable Exchange server without requiring valid credentials.

## 1. Execution

Consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, such as exploring a network or stealing data.

Command and Scripting Interpreter: PowerShell (T1059.001): This scenario encodes a user-defined PowerShell script into base64 and then executes it using PowerShell’s -encodedCommand parameter.

Command and Scripting Interpreter: Visual Basic (T1059.005): This scenario will attempt to execute a Visual Basic Script (VBS) via cscript.exe.

Native API (T1106): This scenario executes the CreateProcessA Windows API call to create a new process of a given executable payload.

Process Injection (T1055): This scenario performs process injection by allocating memory in a running process with VirtualAlloc, writing shellcode to that memory space, and then changing the memory protection option with VirtualProtect.

Hijack Execution Flow: DLL Search Order Hijacking (T1574.001): This scenario takes advantage of Microsoft’s Dynamic-Link Library (DLL) search order to load a rogue DLL into a trusted system binary.

Hijack Execution Flow: DLL Side-Loading (T1574.002):  This scenario leverages a legitimate and trusted executable to load a malicious Dynamic-link Library (DLL).

System Services: Service Execution (T1569.002): This scenario executes a service through the Start-Service PowerShell cmdlet.

## 2. Persistence

Techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access.

Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001): This scenario creates an entry under ```pwshHKLM\Software\Microsoft\Windows\CurrentVersion\Run``` to acquire persistence on the system.

Scheduled Task/Job: Scheduled Task (T1053.005): This scenario creates a new scheduled task using the schtasks utility with the name test3 that was observed being used by Salt Typhoon.

Create or Modify System Process: Windows Service (T1543.003): This scenario creates a service through the New-Service PowerShell cmdlet.

Modify Registry (T1112): This scenario creates a service group by adding a new registry entry under the ```pwshHKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost``` registry key.

## 3. Privilege Escalation

Consists of techniques that adversaries use to gain higher-level permissions on a system or network.

Access Token Manipulation (T1134): This scenario enables the SeDebugPrivilege privilege for the current process using the AdjustTokenPrivilege Windows API.

Access Token Manipulation: Token Impersonation/Theft (T1134.001): This scenario lists and duplicates the access tokens of the running processes available on the target system in order to escalate privileges. It allows the execution of arbitrary commands by impersonating a logged-in user.

## 4. Defense Evasion

Consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts.

Impair Defenses (T1562): This scenario enables WDigest authentication by modifying the ```pwshHKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential``` registry key.

## 5. Credential Access

Consists of techniques for stealing credentials like account names and passwords.

OS Credential Dumping: LSASS Memory (T1003.001): This scenario dumps the Windows Local Security Authority Server Service (LSASS) process memory to a Minidump file using rundll32.exe in combination with comsvcs.dll native Windows library.

## 6. Discovery

Techniques that adversaries use to discover information related to the compromised environment.

Query Registry (T1012): This scenario queries the MachineGUID value located within the ```pwshHKLM\SOFTWARE\Microsoft\Cryptography``` registry key which contains the unique identifier of the system.

Process Discovery (T1057): This scenario enumerates processes running on the target asset through the tasklist Windows utility. The results are saved to a file in a temporary location.

Log Enumeration (T1654): This scenario searches the Windows Event Log for successful login attempts using the wevtutil utility.

System Network Configuration Discovery (T1016): This scenario executes the Windows command ```pwshipconfig /all``` to retrieve information about all network adapters.

System Network Configuration Discovery (T1016): This scenario executes the ```pwshTest-NetConnection``` PowerShell cmdlet to gather network diagnostic information on a compromised Windows system.

Remote System Discovery (T1018): This scenario executes the net view command to gather additional hosts available to the infected asset.

## 7. Lateral Movement

Consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it.

Windows Management Instrumentation (T1047): This scenario attempts to move laterally to any available asset inside the network through the use of WMI. If the remote asset can be accessed, a configurable command is executed.

Windows Management Instrumentation (T1047): This scenario emulates the use of the Impacket utility to execute the WMIEXEC class, facilitating lateral movement via the WMI protocol.

## 8. Command and Control

Techniques that adversaries may use to communicate with systems under their control within a victim network.

BITS Jobs (T1197): This scenario employs the bitsadmin native command to create a BITS job and configure it to download a remote payload. The Background Intelligent Transfer Service (BITS) is a mechanism used by legitimate applications to use a system’s idle bandwidth to retrieve files without disrupting other applications.

Internet Connection Discovery (T1016.001): This scenario executes the certutil utility to try and download a file from a website and save it to a temporary directory.

## 9. Malware Samples

Consists of the malware samples used by Salt Typhoon during its most recent activities.

Ingress Tool Transfer (T1105): This scenario downloads to memory and saves to disk in two separate scenarios to test network and endpoint controls and their ability to prevent the delivery of known malicious samples.

Opportunities to Expand Emulation Capabilities

In addition to the released assessment template, AttackIQ recommends the following scenario to extend the emulation of the capabilities exhibited by Salt Typhoon:

    Execute Power Shell Script in Remote System with PaExec: This scenario simulates the execution of a PowerShell script on a remote machine using PaExec, an open-source version of PSExec.

Detection and Mitigation Opportunities

Given the vast number of techniques used by Salt Typhoon, it can be difficult to know which to prioritize for prevention and detection assessment. AttackIQ recommends first focusing on the following techniques emulated in our scenarios before moving on to the remaining techniques.

    1. Hijack Execution Flow: DLL Side-Loading (T1574.002):

    Adversaries will commonly use Side-Loading to load malicious code into legitimate running processes to attempt to blend in with legitimate applications to remain hidden and appear normal to the compromised system.

    1a. Detection

    Searching for common processes that are performing uncommon actions can help identify when a process has been compromised. Searching for newly constructed processes or monitoring for DLL/PE file events, specifically for the creation and loading of DLLs into running processes can help identify when a system process has been compromised.

    1b. Mitigation

    MITRE ATT&CK recommends the following mitigation recommendations:

        M1013 – Application Developer Guidance
        M1051 – Update Software

    2. Scheduled Task/Job: Scheduled Task (T1053.005):

    Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly from the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel.

    2a. Detection

    With an EDR or SIEM Platform, you can detect the following commands being issued to schedule a malicious task.

    ```consoleProcess Name = (“cmd.exe” OR “Powershell.exe”)
    Command Line CONTAINS (“schtasks” AND “/CREATE” AND (“cmd” OR “powershell”)```

    2b. Mitigation

    MITRE ATT&CK has the following mitigation recommendations for Scheduled Task

        M1047 – Audit
        M1028 – Operating System Configuration
        M1026 – Privileged Account Management
        M1018 – User Account Management

    3. OS Credential Dumping: LSASS Memory (T1003.001):

    Adversaries may attempt to extract user and credential information from the Local Security Authority Subsystem Service (LSASS) process.

    3a. Detection

    Search for executions of comsvcs that attempt to access the LSASS process.

    ```consoleProcess Name == (comsvcs)
    Command Line CONTAINS (‘lsass’)```

    3b. Mitigation

    MITRE ATT&CK recommends the following mitigation recommendations:

        M1028 – Operating System Configuration
        M1027 – Password Policies
        M1026 – Privileged Account Management
        M1017 – User Training
        M1040 – Behavior Prevention on Endpoint
        M1043 – Credential Access Protection
        M1025 – Privileged Process Integrity
