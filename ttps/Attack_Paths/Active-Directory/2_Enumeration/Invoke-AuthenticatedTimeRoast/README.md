# Authenticated TimeRoast (PowerShell)

Slightly altered version of the TimeRoast PowerShell script originally published by Secura:  
https://github.com/SecuraBV/Timeroast

This script performs SNTP-based time roasting against a Domain Controller (DC), targeting computer accounts via their RIDs and resolving those RIDs to hostnames using LDAP enumeration. The output includes hashes in a format compatible with Hashcat (`$sntp-ms$`) and includes the associated computer hostname for easier identification.

> ⚠️ Requires the **beta version of hashcat** for cracking mode 31300: https://hashcat.net/beta

## Requirements
- Requires executing from a domain account

## Modifications from the Original

- LDAP is used to resolve computer account names and extract RIDs.
- Output format includes the resolved **hostname** instead of just the RID.
- Added optional **wordlist generation** of sAMAccountNames (lowercased, no trailing `$`).

## Usage

```powershell
# Basic usage
Invoke-AuthenticatedTimeRoast -DomainController "dc01.security.local"

# Save output to file and generate wordlist
Invoke-AuthenticatedTimeRoast -DomainController "dc01.security.local" -OutputFile hashes.log -GenerateWordlist
```

## Cracking

```bash
hashcat.exe -m 31300 -a 0 -O Hashes\hash.txt Wordlists\rockyou.txt -r rules\best64.rule --username
```

## References

- Original tool by Secura: [https://github.com/SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- Hashcat Beta Download: [https://hashcat.net/beta](https://hashcat.net/beta)
- Further information: https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/timeroasting
