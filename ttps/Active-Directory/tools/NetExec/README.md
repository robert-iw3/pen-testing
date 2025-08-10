# NetExec - The Network Execution Tool

This project was initially created in 2015 by @byt3bl33d3r, known as CrackMapExec. In 2019 @mpgn_x64 started maintaining the project for the next 4 years, adding a lot of great tools and features. In September 2023 he retired from maintaining the project.

Along with many other contributors, we (NeffIsBack, Marshall-Hallenbeck, and zblurx) developed new features, bug fixes, and helped maintain the original project CrackMapExec.
During this time, with both a private and public repository, community contributions were not easily merged into the project. The 6-8 month discrepancy between the code bases caused many development issues and heavily reduced community-driven development.
With the end of mpgn's maintainer role, we (the remaining most active contributors) decided to maintain the project together as a fully free and open source project under the new name **NetExec** 🚀
Going forward, our intent is to maintain a community-driven and maintained project with regular updates for everyone to use.

# Documentation, Tutorials, Examples
See the project's [wiki](https://netexec.wiki/) (in development) for documentation and usage examples

## Linux
```bash
podman build -t netexec .
podman run -it --name netexec netexec

nxc -h

usage: nxc [-h] [-t THREADS] [--timeout TIMEOUT] [--jitter INTERVAL] [--no-progress] [--verbose] [--debug] [--version] {smb,ssh,ldap,ftp,wmi,winrm,rdp,vnc,mssql} ...

    <-- Banner -->

options:
  -h, --help            show this help message and exit
  -t THREADS            set how many concurrent threads to use (default: 100)
  --timeout TIMEOUT     max timeout in seconds of each thread (default: None)
  --jitter INTERVAL     sets a random delay between each connection (default: None)
  --no-progress         Not displaying progress bar during scan
  --verbose             enable verbose output
  --debug               enable debug level information
  --version             Display nxc version

protocols:
  available protocols

  {smb,ssh,ldap,ftp,wmi,winrm,rdp,vnc,mssql,nfs}
    smb                 own stuff using SMB
    ssh                 own stuff using SSH
    ldap                own stuff using LDAP
    ftp                 own stuff using FTP
    wmi                 own stuff using WMI
    winrm               own stuff using WINRM
    rdp                 own stuff using RDP
    vnc                 own stuff using VNC
    mssql               own stuff using MSSQL
    nfs                 own stuff using NFS
```
