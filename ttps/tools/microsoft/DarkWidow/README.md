# DarkWidow

A Customizable Dropper Tool targeting Windows.

-----

### Honourable Mentions:
1. [BlackHat Asia, 2024 - Call For Tools](https://www.blackhat.com/asia-24/arsenal/schedule/presenters.html#soumyanil-biswas-47163)
2. [BlackHat USA, 2024 - Call For Tools](https://www.blackhat.com/us-24/arsenal/schedule/presenters.html#soumyanil-biswas-47163)
3. [BlackHat SecTor, 2024 - Call For Tools](https://www.blackhat.com/sector/2024/arsenal/schedule/presenters.html#soumyanil-biswas-47163)
4. [BlackHat Europe, 2024 - Call For Tools](https://www.blackhat.com/eu-24/arsenal/schedule/index.html#darkwidow-customizable-dropper-tool-targeting-windows-41187)
5. [Wild West Hacking Fest 2024 - Arsenal](https://wildwesthackinfest.com/agenda-for-wwhf-2024-deadwood/)

- Thanks a lot to Soumyadeep Da aka [@SoumyadeepBas12](https://twitter.com/SoumyadeepBas12) for encouraging me to apply for these conferences, else I wouldn't have done it :)
- Thanks a lot to Faran aka [@Chrollo_l33t](https://twitter.com/Chrollo_l33t) for helping me to create the Slides and PPT for the presentation for this tool :)
-----

### Capabilities:

1. Indirect Dynamic Syscall. (MITRE ATT&CK TTP: [T1106](https://attack.mitre.org/techniques/T1106/))
2. SSN + Syscall address sorting via Modified TartarusGate approach
3. Remote Process Injection via APC Early Bird to CUT OFF telemetry Catching by EDR. (**MITRE ATT&CK TTP: [T1055.004](https://attack.mitre.org/techniques/T1055/004/)**)
4. Spawns a sacrificial Process as the target process, not disrupting already open processes in the environment.
5. ACG(Arbitrary Code Guard)/BlockDll mitigation policy on spawned sacrificial process.
6. PPID spoofing (**MITRE ATT&CK TTP: [T1134.004](https://attack.mitre.org/techniques/T1134/004/)**)
7. Api and Dll resolving from TIB (Directly via offset (from TIB) -> TEB -> PEB -> resolve Nt Api) (**MITRE ATT&CK TTP: [T1106](https://attack.mitre.org/techniques/T1106/)**)
8. Cursed Nt API hashing (MITRE ATT&CK ID: [S0574](https://attack.mitre.org/software/S0574/))

### Bonus: If blessed with Admin privilege =>

1. Disables Event Log via _killing_ EventLog Service Threads (**MITRE ATT&CK TTP: [T1562.002](https://attack.mitre.org/techniques/T1562/002/)**)
> **Disadv**: If threads are resumed, all events that occurred during the suspension of Event Logger, get logged Again!

**So, thought of killing them instead!**
> "It's more Invasive than suspension, but the decision is always up to the operator. Besides, killing threads get logged on the kernel level" - [@SEKTOR7net](https://twitter.com/Sektor7Net)

#### While Killing only those threads in the indirect syscall implant, was facing an error. I was unable to get the "**eventlog**" _SubProcessTag Value_. So thought of killing all threads, i.e. killing the whole process (responsible **svchost.exe**). Yeah creating ***an IOC***!.

### =
### 1. EDR/Ring-3/UserLand hook Bypass
### 2. The syscall and return statement are executed from memory of ntdll.dll
### 3. EDR detection based on checking the return address in the call stack can be bypassed.

### Compile:
1.
```
Directly via VS compiler:
```
![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/622c39a1-c3b3-4388-ad3a-5a36d18e29ff)

#### Also add **/MT** compiler flag! => To statically links CRT functions together in a binary (Yeah, U guessed it, it bloats the implant)

![image](https://github.com/reveng007/DarkWidow/assets/61424547/58e9a9d4-e068-4364-8114-96744bdbc0a7)

2. Also via compile.bat (prefer option 1.)
```
./compile.bat
```

### Usage:
```
PS C:> .\x64\Release\indirect.exe
[!] Wrong!
[->] Syntax: .\x64\Release\indirect.exe <PPID to spoof>
```
### In Action:

https://github.com/reveng007/DarkWidow/assets/61424547/62a90c5b-84af-4389-8ddc-9f7926debdcf

### Successful Execution WithOut Creating Alert on Sofos XDR EndPoint:

![SofosXDREvade](https://github.com/reveng007/DarkWidow/assets/61424547/80744d51-3c93-4399-8b20-a112866a5d64)

-----

### Further Improvements:
1. PPID spoofing (**Emotet method**)
2. ***Much Stealthier*** Use Case of EventLog Disabling!
-----

### Portions of the Code and links those helped:

1. TIB:
   - https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
   - https://www.wikiwand.com/en/Win32_Thread_Information_Block
2. GS and FS register:
   - https://stackoverflow.com/questions/39137043/what-is-the-gs-register-used-for-on-windows
   - https://stackoverflow.com/questions/10810203/what-is-the-fs-gs-register-intended-for#:~:text=The%20registers%20FS%20and%20GS,to%20access%20thread%2Dspecific%20memory.
3. PEB LDR structure:
   - [BlackHat - What Malware Authors Don't Want You to Know - Evasive Hollow Process Injection](https://www.youtube.com/watch?v=9L9I1T5QDg4&t=205s) by [@monnappa22](https://twitter.com/monnappa22)
   - A pic of process Memory from the Above link:\
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/1.png)

   - From [labs.cognisys.group](https://labs.cognisys.group/posts/Combining-Indirect-Dynamic-Syscalls-and-API-Hashing/#retrieving-apis-base-address), a blog by [@D1rkMtr
](https://twitter.com/D1rkMtr):\
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/2.png)

4. TIB -> TEB -> PEB -> Resolve Nt API and API hashing
   - https://stackoverflow.com/questions/41277888/iterating-over-peb-dllname-shows-only-exe-name
   - https://doxygen.reactos.org/d7/d55/ldrapi_8c_source.html#l01124
   - [labs.cognisys.group](https://labs.cognisys.group/posts/Combining-Indirect-Dynamic-Syscalls-and-API-Hashing/#retrieving-apis-base-address), a blog by [@D1rkMtr
](https://twitter.com/D1rkMtr)
   - A pic of the snippet from the above link, which I used here to resolve API dynamically without HardCoding Offsets:\
     ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/3.png)

   - The Api hashing code that I applied:
```cpp

#include <stdint.h>
#include <stdio.h>
#include <windows.h>

DWORD64 djb2(const char* str)
{
	DWORD64 dwHash = 0x7734773477347734;
	int c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;


	return dwHash;
}

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("[!] Wrong!\n");
		printf("[->] Syntax: .\\%s <NTFuncName>\n\n", argv[0]);
		return 1;
	}

	const char* string = argv[1];

	DWORD64 hashvalue = djb2(string);

	printf("Hash Value: 0x%llX\n", hashvalue);

	return 0;
}

```

5. ACG(Arbitrary Code Guard)/BlockDll mitigation policy:
   - links:
   - [Protecting Your Malware](https://blog.xpnsec.com/protecting-your-malware/) by [@_xpn_](https://twitter.com/_xpn_)
   - [Wraith](https://github.com/reveng007/AQUARMOURY/blob/1923e65190875f7c61c76fb430d526e5deaa062a/Wraith/Src/Injector.h) by [@winterknife](https://twitter.com/_winterknife_)
   - [spawn](https://github.com/boku7/spawn) and [HOLLOW](https://github.com/boku7/HOLLOW) by [@0xBoku](https://twitter.com/0xBoku)
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/4.png)

6. PPID Spoofing Detection:
   - [PPID Spoofing Detect](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing) by [@spotheplanet](https://twitter.com/spotheplanet)
   - If got time, I will be adding a detection Portion to this portion! -> _[Remaining..............................................!]_

7. Moneta Detection and PESieve Detection:\
   - **Moneta**:\
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/5.png)

   - **PESieve**:\
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/6.png)

8. Capa Scan:\
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/7.png)

9. How Thread Stack Looks of the Implant Process:

| Implant Process  |   Legit Cmd process    |
| ---------------- | ---------------- |
|  ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/8.png) | ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/9.png) |

> **It follows that by executing the return instruction in the memory of the ntdll.dll in the indirect syscall POC, the return address can be successfully spoofed, the ntdll.dll can be placed at the top of the call stack and the EDR will interpret a higher legitimacy.** - [@VirtualAllocEx](https://twitter.com/VirtualAllocEx) from [DirectSyscall Vs Indirect Syscall](https://redops.at/blog/direct-syscalls-vs-indirect-syscalls)\
Also thanks to, [@peterwintrsmith](https://twitter.com/peterwintrsmith)!

10. Instrumentation CallBack Evasion: Used this [POC - syscall-detect](https://github.com/jackullrich/syscall-detect) by [winternl_t](https://twitter.com/winternl_t)

![image](https://github.com/reveng007/DarkWidow/assets/61424547/2869180b-a0fe-416a-95b3-c4b81565aa8f)

11. EventLogger Config, I used:

![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/10.png)
![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/11.jpg)

13. Setting SeDebugPrivilege:\
   **From** Here:
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/11.png)
   **To** Here:
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/12.png)

14. Killing Event Log Threads:
    - [rto-win-evasion](https://institute.sektor7.net/rto-win-evasion) by [@SEKTOR7net](https://twitter.com/Sektor7Net)
    - [Phant0m](https://github.com/hlldz/Phant0m) by [@hlldz](https://twitter.com/hlldz)
    - [Goblin](https://github.com/reveng007/AQUARMOURY/blob/master/Goblin/Src/EventLog.h) by [@winterknife](https://twitter.com/_winterknife_)
    - [disabling-windows-event-logs-by-suspending-eventlog-service-threads](https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads) by [@spotheplanet](https://twitter.com/spotheplanet)\
    **From** here:\
    ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/13.png)\
    **To** here:\
    ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/14.png)
    - **This Method, Ended up causing errors in indirect syscall implementation. So, I ended up killing all those threads present within responsible svchost.exe** (reason: [Go up](https://github.com/reveng007/DarkWidow/edit/main/README.md#bonus-if-blessed-with-admin-privilege-)).

### Sophos XDR Event Loging Scenario:

1. Case 1: When Darkwidow executed under normal privilege

![image](https://github.com/reveng007/DarkWidow/assets/61424547/4a2c3dde-7eac-4828-a0be-90f7427c1d65)

> No Critical Alerts gets created except One Low Severity Log!

2. Case 2: When Darkwidow executed under Admin privilege

![image](https://github.com/reveng007/DarkWidow/assets/61424547/4e6c84b6-0cb2-47d2-b74a-1b01b9126299)

> One Low Severity Log => APC Injection (Like Before)

![image](https://github.com/reveng007/DarkWidow/assets/61424547/89924920-3766-4395-a186-6705cf7e84d3)

> Another one which is a Medium Severity Log occured for setting `SeDebugPrivilege`.

![image](https://github.com/reveng007/DarkWidow/assets/61424547/7a36d21e-559c-40c5-985b-cdd22eda204e)

# DarkWidow V2:

#### To get around this Event Logging Detection, I added the concept of `Synthetic Frame Thread Stack Spoofing` into it.

This is how stack looks after applying synthetic frame thread stack spoofing.

![image](https://github.com/reveng007/DarkWidow/assets/61424547/9d978a9d-ee01-4379-9bc6-87caa37e5255)
> This is the NT api Thread Stack

![image](https://github.com/reveng007/DarkWidow/assets/61424547/b9c24f7e-abfb-4f5e-89b5-35225d49d53d)
> This is the shellcode (btw, this is not custom made, this is Havoc Shellcode :)) thread stack.

For shellcode development, I have used havoc and this below configuration:

![image](https://github.com/reveng007/DarkWidow/assets/61424547/f17ae8ba-205e-41fa-b144-b81305fe29eb)

### NOTE:
Newly Created Thread Start Address Spoofing was not really required in this project cause within APC Injection technique, APC hijacks the execution of an already and legit running thread. Thanks to [@C5pider](https://twitter.com/C5pider)!

### Demo Execution Pic:

![1708744707672](https://github.com/reveng007/DarkWidow/assets/61424547/0ab56b7c-9365-4837-95e4-f172cbab8e61)

### Demo Video against Sophos XDR:

[![Demo Video Youtube Link](https://img.youtube.com/vi/HqtXD3CJg9k/0.jpg)](https://www.youtube.com/watch?v=HqtXD3CJg9k)

Now Status On Event Logs ?

![image](https://github.com/reveng007/DarkWidow/assets/61424547/375e8d6d-ac45-4959-bfb9-bc0fdc71f0ed)

> No logs got generated.
> I also have removed the Event Logger Killing part from the DarkWidow V2, which decreases down the Event generation too!

### My BlackHat Arsenal Demo Video can be found in here:

[![Demo Video Youtube Link](https://img.youtube.com/vi/1mserrlZHEE/0.jpg)](https://www.youtube.com/watch?v=1mserrlZHEE)

### My WildWestHackinFest Presentation Slide can be found in here:

[Google Slide link](https://docs.google.com/presentation/d/1Qel94kLSzSctwe8BeYCCo5yZAijtjZqzg7uC2HIbkFQ/edit?usp=sharing)

### Future Updates to this:

1. Porting this version to C++ Clang Compiler, which would help us to perform LLVM obfuscation.
2. Upgrading to NtCreateUserProcess() to perform indirect syscall and stack spoofing.
3. Applying Manual Load Library capability for bypassing Image Load Kernel Callbacks.
4. Applying Module Stomping capability.
5. Encrypted shellcode Injection to avoid Kernel triggered memory scans ([Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann)).


### Major Thanks for helping me out (Directly/indirectly (pun NOT intended :))):

1. [@SEKTOR7net](https://twitter.com/Sektor7Net)
2. [@peterwintrsmith](https://twitter.com/peterwintrsmith)
3. [@Jean_Maes_1994](https://twitter.com/Jean_Maes_1994)
4. [@D1rkMtr](https://twitter.com/D1rkMtr)
5. [@spotheplanet](https://twitter.com/spotheplanet)
6. [@0xBoku](https://twitter.com/0xBoku)
7. [@Sh0ckFR](https://twitter.com/Sh0ckFR)
8. [@winterknife](https://twitter.com/_winterknife_)
9. [@monnappa22](https://twitter.com/monnappa22)
10. [@_xpn_](https://twitter.com/_xpn_)
11. [@hlldz](https://twitter.com/hlldz)
12. [@d_tranman](https://twitter.com/d_tranman)
13. [@SoumyadeepBas12](https://twitter.com/SoumyadeepBas12)
14. [@jack_halon](https://twitter.com/jack_halon)
15. [@KlezVirus](https://twitter.com/KlezVirus)
16. [@C5pider](https://twitter.com/C5pider)

I hope I didn't miss someone!

### This project is a part of my journey to learn about EDR World! => [Learning-EDR-and-EDR_Evasion](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion)

