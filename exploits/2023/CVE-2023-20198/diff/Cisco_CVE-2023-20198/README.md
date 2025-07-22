# CVE-2023-20198
CVE-2023-20198 Checkscript based on:
- Technical analysis: https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/
- First script version: https://github.com/Atea-Redteam/CVE-2023-20198/

Thanks to Atea Redteam for their work.

Requires:
- Python3.7+
- Python libs: ipaddress, requests, subprocess, re, argparse 

Different ways to launch the script:
- Scan a subnet with CIDR notation:
./CVE-2023-20198.py -c 172.16.0.0/8

- Scan a single IP address:
./CVE-2023-20198.py -a 172.16.0.254

- Scan multiple IP addresses included into a file:
./CVE-2023-20198.py -f ips.txt


IPs with status code 200, suspicious length, and malicious impant confirmed:
['172.16.0.254']

IPs with status code 200, but doesn't seems to be pwned:
[]

Results will be added into results.csv as well.
