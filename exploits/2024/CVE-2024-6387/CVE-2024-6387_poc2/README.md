# CVE-2024-6387 Proof of Concept (PoC)

## Description

This repository contains a PoC for vulnerability CVE-2024-6387, which targets a signal handler race condition in the OpenSSH server (sshd) on glibc-based Linux systems. The vulnerability allows remote code execution as root by calling asynchronous-signal-insecure functions in the SIGALRM handler.


Clone the repository and use:
```bash
   git clone https://github.com/jocker2410/CVE-2024-6387_poc.git && cd CVE-2024-6387_poc
   # adapt the ip-addr.list file and insert the appropriate IP address. Please note the spelling, you must either insert simple IPv4 addresses or with port separated by a colon.
   
   python3 CVE-2024-6387_poc.py
```

🚀 only test your own system and have fun with it ;) 🚀
