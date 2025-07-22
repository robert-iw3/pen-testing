# SpeechRuntimeMove
Lateral Movement via SpeechRuntime DCOM trigger & COM Hijacking.

This Proof of Concept (PoC) for Lateral Movement abuses the fact, that some COM Classes configured as `INTERACTIVE USER` will spawn a process in the context of the currently logged on users session.

If those processes are also vulnerable to COM Hijacking, we can configure a COM Hijack via the remote registry, drop a malicious DLL via SMB and trigger loading/execution of this DLL via DCOM.

This technique removes the need to takeover the system plus afterward:
1) Impersonate the target user
2) Steal the target users credentials from LSASS or somewhere else
3) or use alternative techniques to take over the account

Because our code is already getting executed in the context of the logged in user, we can do whatever we want in that context and create less IoCs for alternative techniques.

In this PoC, the CLSID `38FE8DFE-B129-452B-A215-119382B89E3D` - Speech Named Pipe COM is used with the IID `ISpeechNamedPipe`. `SpeechRuntime.exe` will be spawned whenever an instance of the Speech Named Pipe COM Class is created, which is vulnerable to COM Hijacking:

<br>
<div align="center">
    <img src="https://github.com/rtecCyberSec/SpeechRuntimeMove/blob/main/images/COMHijack.png?raw=true" width="500">
</div>
<br>


The CLSID `655D9BF9-3876-43D0-B6E8-C83C1224154C` (and many more) are looked for under `HKCU`, which we can hijack from remote.

# Enum Mode

To find out, which users are active on a remote client you can use the enum mode like this:

```bash
SpeechRuntimeMove.exe mode=enum target=<targetHost>
```

# Attack mode

To actually execute code on the remote system, you need to specify the target username, the Session number, the DLL drop path as well as the command to execute:

```bash
SpeechRuntimeMove.exe mode=attack target=<targetHost> dllpath=C:\windows\temp\pwned.dll session=2 targetuser=local\domadm command="cmd.exe /C calc.exe"
```

# OpSec considerations / Detection

The PoC uses a hardcoded DLL, which will always look the same and which will get dropped on the target. It's super easy to build detections on this DLL, so using a self written DLL will less likely get you detected.
With a custom DLL you will also live in a trusted signed process instead of spawning a new one, that's usually what attackers prefer.

Behavior based detection of this technique can be done by checking for
1) Remote COM Hijack of the mentioned CLSID followed by
2) `SpeechRuntime.exe` loading a newly dropped DLL from the hijack location
3) `SpeechRuntime.exe` spawning suspicious sub-processes

