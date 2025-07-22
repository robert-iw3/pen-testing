# Elevation-BOF

BOFs for context elevation

![](_img/01.png)



## getsystem token

Elevate the current agent to SYSTEM and gain the TrustedInstaller group privilege through impersonation

```
getsystem token
```

![](_img/02.png)



## uacbybass sspi

Forges a token from a fake network authentication though SSPI Datagram  Contexts. It will then impersonate the forged token and use CreateSvcRpc by [@x86matthew](https://twitter.com/x86matthew) to create a new SYSTEM service. Original research and code is from [@splinter_code](https://twitter.com/splinter_code).

```
uacbybass sspi <file.exe>
```

![](_img/03.png)



## uacbypass registryshellcmd

Modifies the "ms-settings\Shell\Open\command" registry key and executes an auto-elevated EXE (ComputerDefaults.exe).

```
uacbypass registryshellcmd <file.exe>
```

![](_img/04.png)



## Credits

* Elevate-System-Trusted-BOF - https://github.com/Mr-Un1k0d3r/Elevate-System-Trusted-BOF
* UAC-BOF-Bonanza - https://github.com/icyguider/UAC-BOF-Bonanza