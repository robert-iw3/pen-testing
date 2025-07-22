# CVE-2024-4956-Sonatype-Nexus-Repository-Manager

**Sonatype Nexus Repository Manager** provides a central platform for storing build artifacts

**CVE-2024-4956** is a path traversal vulnerability in Sonatype Nexus Repository manager that allows an attacker to craft a URL to return any file as a download, including system files outside of Nexus Repository application scope, without any authentication.

**Affected Versions**:  All previous Sonatype Nexus Repository 3.x OSS/Pro versions up to and including 3.68.0

**Python3 exploit Usage**: python3 exploitPython.py -u -p -f

**Python3 exploit Usage example**: python3 exploitPython.py -u http://127.0.0.1 -p 8081 -f /etc/passwd

**Bash exploit Usage**: ./exploitBash.sh -u targetUrl -p targetPort -f targetFile

**Bash exploit Usage example**: ./exploitBash.sh -u https://127.0.0.1 -p 8081 -f /etc/passwd

**Disclaimer**: This exploit is to be used only for educational and authorized testing purposes. Illegal/unauthorized use of this exploit is prohibited.

**References**: 
https://support.sonatype.com/hc/en-us/articles/29416509323923-CVE-2024-4956-Nexus-Repository-3-Path-Traversal-2024-05-16
https://nvd.nist.gov/vuln/detail/CVE-2024-4956
https://exp10it.io/2024/05/%E9%80%9A%E8%BF%87-java-fuzzing-%E6%8C%96%E6%8E%98-nexus-repository-3-%E7%9B%AE%E5%BD%95%E7%A9%BF%E8%B6%8A%E6%BC%8F%E6%B4%9E-cve-2024-4956/
