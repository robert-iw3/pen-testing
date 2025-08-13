```sh
$ nmap -sV --script=vulscan/vulscan.nse rest.vulnweb.com



Starting Nmap 7.97 ( https://nmap.org ) at 2025-06-23 21:20 +0000
Nmap scan report for rest.vulnweb.com (18.215.71.186)
Host is up (0.030s latency).
rDNS record for 18.215.71.186: ec2-18-215-71-186.compute-1.amazonaws.com
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
| vulscan: VulDB - https://vuldb.com:
| [160579] Apache Cassandra up to 2.1.21/2.2.17/3.0.21/3.11.7/4.0-beta1 RMI Registry exposure of resource
| [121358] Apache Spark up to 2.1.2/2.2.1/2.3.0 PySpark/SparkR information disclosure
| [113146] Apache CouchDB 2.0.0 Windows Installer nssm.exe access control
| [99052] Apache Ambari up to 2.3.x kadmin information disclosure
| [87539] Apache Ambari up to 2.1.1 Agent data access control
| [79073] Apache Ambari up to 2.0 Config File Password information disclosure
| [79072] Apache Ambari up to 2.0 Config Screen Password information disclosure
| [60632] Debian apache2 2.2.16-6/2.2.22-1/2.22-3 mod_php cross site scripting
| [55501] Apache Mod Fcgid up to 2.3.2 mod_fcgid fcgid_bucket.c fcgid_header_bucket_read numeric error
| [23524] Apache James 2.2.0 Foundation retrieve memory leak
|
| MITRE CVE - https://cve.mitre.org:
| [CVE-2012-0883] envvars (aka envvars-std) in the Apache HTTP Server before 2.4.2 places a zero-length directory name in the LD_LIBRARY_PATH, which allows local users to gain privileges via a Trojan horse DSO in the current working directory during execution of apachectl.
| [CVE-2013-2249] mod_session_dbd.c in the mod_session_dbd module in the Apache HTTP Server before 2.4.5 proceeds with save operations for a session without considering the dirty flag and the requirement for a new session ID, which has unspecified impact and remote attack vectors.
| [CVE-2012-4558] Multiple cross-site scripting (XSS) vulnerabilities in the balancer_handler function in the manager interface in mod_proxy_balancer.c in the mod_proxy_balancer module in the Apache HTTP Server 2.2.x before 2.2.24-dev and 2.4.x before 2.4.4 allow remote attackers to inject arbitrary web script or HTML via a crafted string.
| [CVE-2012-3502] The proxy functionality in (1) mod_proxy_ajp.c in the mod_proxy_ajp module and (2) mod_proxy_http.c in the mod_proxy_http module in the Apache HTTP Server 2.4.x before 2.4.3 does not properly determine the situations that require closing a back-end connection, which allows remote attackers to obtain sensitive information in opportunistic circumstances by reading a response that was intended for a different client.
| [CVE-2012-3499] Multiple cross-site scripting (XSS) vulnerabilities in the Apache HTTP Server 2.2.x before 2.2.24-dev and 2.4.x before 2.4.4 allow remote attackers to inject arbitrary web script or HTML via vectors involving hostnames and URIs in the (1) mod_imagemap, (2) mod_info, (3) mod_ldap, (4) mod_proxy_ftp, and (5) mod_status modules.
| [CVE-2012-3451] Apache CXF before 2.4.9, 2.5.x before 2.5.5, and 2.6.x before 2.6.2 allows remote attackers to execute unintended web-service operations by sending a header with a SOAP Action String that is inconsistent with the message body.
| [CVE-2012-2687] Multiple cross-site scripting (XSS) vulnerabilities in the make_variant_list function in mod_negotiation.c in the mod_negotiation module in the Apache HTTP Server 2.4.x before 2.4.3, when the MultiViews option is enabled, allow remote attackers to inject arbitrary web script or HTML via a crafted filename that is not properly handled during construction of a variant list.
| [CVE-2012-2379] Apache CXF 2.4.x before 2.4.8, 2.5.x before 2.5.4, and 2.6.x before 2.6.1, when a Supporting Token specifies a child WS-SecurityPolicy 1.1 or 1.2 policy, does not properly ensure that an XML element is signed or encrypted, which has unspecified impact and attack vectors.
| [CVE-2012-2378] Apache CXF 2.4.5 through 2.4.7, 2.5.1 through 2.5.3, and 2.6.x before 2.6.1, does not properly enforce child policies of a WS-SecurityPolicy 1.1 SupportingToken policy on the client side, which allows remote attackers to bypass the (1) AlgorithmSuite, (2) SignedParts, (3) SignedElements, (4) EncryptedParts, and (5) EncryptedElements policies.
| [CVE-2011-2516] Off-by-one error in the XML signature feature in Apache XML Security for C++ 1.6.0, as used in Shibboleth before 2.4.3 and possibly other products, allows remote attackers to cause a denial of service (crash) via a signature using a large RSA key, which triggers a buffer overflow.
|
| SecurityFocus - https://www.securityfocus.com/bid/:
| [42102] Apache 'mod_proxy_http' 2.2.9 for Unix Timeout Handling Information Disclosure Vulnerability
| [27237] Apache HTTP Server 2.2.6, 2.0.61 and 1.3.39 'mod_status' Cross-Site Scripting Vulnerability
| [15413] PHP Apache 2 Virtual() Safe_Mode and Open_Basedir Restriction Bypass Vulnerability
| [15177] PHP Apache 2 Local Denial of Service Vulnerability
| [6065] Apache 2 WebDAV CGI POST Request Information Disclosure Vulnerability
| [5816] Apache 2 mod_dav Denial Of Service Vulnerability
| [5486] Apache 2.0 CGI Path Disclosure Vulnerability
| [5485] Apache 2.0 Path Disclosure Vulnerability
| [5434] Apache 2.0 Encoded Backslash Directory Traversal Vulnerability
| [5256] Apache httpd 2.0 CGI Error Path Disclosure Vulnerability
| [4057] Apache 2 for Windows OPTIONS request Path Disclosure Vulnerability
| [4056] Apache 2 for Windows php.exe Path Disclosure Vulnerability
|
| IBM X-Force - https://exchange.xforce.ibmcloud.com:
| [75211] Debian GNU/Linux apache 2 cross-site scripting
|
| Exploit-DB - https://www.exploit-db.com:
| [31052] Apache <= 2.2.6 'mod_negotiation' HTML Injection and HTTP Response Splitting Vulnerability
| [30901] Apache HTTP Server 2.2.6 Windows Share PHP File Extension Mapping Information Disclosure Vulnerability
| [30835] Apache HTTP Server <= 2.2.4 413 Error HTTP Request Method Cross-Site Scripting Weakness
| [28424] Apache 2.x HTTP Server Arbitrary HTTP Request Headers Security Weakness
| [28365] Apache 2.2.2 CGI Script Source Code Information Disclosure Vulnerability
| [27915] Apache James 2.2 SMTP Denial of Service Vulnerability
| [27135] Apache Struts 2 DefaultActionMapper Prefixes OGNL Code Execution
| [26710] Apache CXF prior to 2.5.10, 2.6.7 and 2.7.4 - Denial of Service
| [24590] Apache 2.0.x mod_ssl Remote Denial of Service Vulnerability
| [23581] Apache 2.0.4x mod_perl Module File Descriptor Leakage Vulnerability
| [23482] Apache 2.0.4x mod_php Module File Descriptor Leakage Vulnerability (2)
| [23481] Apache 2.0.4x mod_php Module File Descriptor Leakage Vulnerability (1)
| [23296] Red Hat Apache 2.0.40 Directory Index Default Configuration Error
| [23282] apache cocoon 2.14/2.2 - Directory Traversal vulnerability
| [22191] Apache Web Server 2.0.x MS-DOS Device Name Denial of Service Vulnerability
| [21854] Apache 2.0.39/40 Oversized STDERR Buffer Denial of Service Vulnerability
| [21719] Apache 2.0 Path Disclosure Vulnerability
| [21697] Apache 2.0 Encoded Backslash Directory Traversal Vulnerability
| [20272] Apache 1.2.5/1.3.1,UnityMail 2.0 MIME Header DoS Vulnerability
| [19828] Cobalt RaQ 2.0/3.0 Apache .htaccess Disclosure Vulnerability
| [18984] Apache Struts <= 2.2.1.1 - Remote Command Execution
| [18329] Apache Struts2 <= 2.3.1 - Multiple Vulnerabilities
| [17691] Apache Struts < 2.2.0 - Remote Command Execution
| [15319] Apache 2.2 (Windows) Local Denial of Service
| [14617] Apache JackRabbit 2.0.0 webapp XPath Injection
| [11650] Apache 2.2.14 mod_isapi Dangling Pointer Remote SYSTEM Exploit
| [8458] Apache Geronimo <= 2.1.3 - Multiple Directory Traversal Vulnerabilities
| [5330] Apache 2.0 mod_jk2 2.0.2 - Remote Buffer Overflow Exploit (win32)
| [3996] Apache 2.0.58 mod_rewrite Remote Overflow Exploit (win2k3)
| [2237] Apache < 1.3.37, 2.0.59, 2.2.3 (mod_rewrite) Remote Overflow PoC
| [1056] Apache <= 2.0.49 Arbitrary Long HTTP Headers Denial of Service
| [855] Apache <= 2.0.52 HTTP GET request Denial of Service Exploit
| [132] Apache 1.3.x - 2.0.48 - mod_userdir Remote Users Disclosure Exploit
| [38] Apache <= 2.0.45 APR Remote Exploit -Apache-Knacker.pl
| [34] Webfroot Shoutbox < 2.32 (Apache) Remote Exploit
| [11] Apache <= 2.0.44 Linux Remote Denial of Service Exploit
| [9] Apache HTTP Server 2.x Memory Leak Exploit
|
| OpenVAS (Nessus) - http://www.openvas.org:
| [855524] Solaris Update for Apache 2 120544-14
| [855077] Solaris Update for Apache 2 120543-14
| [100858] Apache 'mod_proxy_http' 2.2.9 for Unix Timeout Handling Information Disclosure Vulnerability
| [72626] Debian Security Advisory DSA 2579-1 (apache2)
| [71551] Gentoo Security Advisory GLSA 201206-25 (apache)
| [71550] Gentoo Security Advisory GLSA 201206-24 (apache tomcat)
| [71485] Debian Security Advisory DSA 2506-1 (libapache-mod-security)
| [71256] Debian Security Advisory DSA 2452-1 (apache2)
| [71238] Debian Security Advisory DSA 2436-1 (libapache2-mod-fcgid)
| [70724] Debian Security Advisory DSA 2405-1 (apache2)
| [70235] Debian Security Advisory DSA 2298-2 (apache2)
| [70233] Debian Security Advisory DSA 2298-1 (apache2)
| [69988] Debian Security Advisory DSA 2279-1 (libapache2-mod-authnz-external)
| [69338] Debian Security Advisory DSA 2202-1 (apache2)
| [65131] SLES9: Security update for Apache 2 oes/CORE
| [64426] Gentoo Security Advisory GLSA 200907-04 (apache)
| [61381] Gentoo Security Advisory GLSA 200807-06 (apache)
| [60582] Gentoo Security Advisory GLSA 200803-19 (apache)
| [58745] Gentoo Security Advisory GLSA 200711-06 (apache)
| [57851] Gentoo Security Advisory GLSA 200608-01 (apache)
| [56246] Gentoo Security Advisory GLSA 200602-03 (Apache)
| [55392] Gentoo Security Advisory GLSA 200509-12 (Apache)
| [55129] Gentoo Security Advisory GLSA 200508-15 (apache)
| [54739] Gentoo Security Advisory GLSA 200411-18 (apache)
| [54724] Gentoo Security Advisory GLSA 200411-03 (apache)
| [54712] Gentoo Security Advisory GLSA 200410-21 (apache)
| [54689] Gentoo Security Advisory GLSA 200409-33 (net=www/apache)
| [54677] Gentoo Security Advisory GLSA 200409-21 (apache)
| [54610] Gentoo Security Advisory GLSA 200407-03 (Apache)
| [54601] Gentoo Security Advisory GLSA 200406-16 (Apache)
| [54590] Gentoo Security Advisory GLSA 200406-05 (Apache)
| [54582] Gentoo Security Advisory GLSA 200405-22 (Apache)
| [54529] Gentoo Security Advisory GLSA 200403-04 (Apache)
| [54499] Gentoo Security Advisory GLSA 200310-04 (Apache)
| [54498] Gentoo Security Advisory GLSA 200310-03 (Apache)
| [11092] Apache 2.0.39 Win32 directory traversal
| [66081] SLES11: Security update for Apache 2
| [66074] SLES10: Security update for Apache 2
| [66070] SLES9: Security update for Apache 2
| [65893] SLES10: Security update for Apache 2
| [65888] SLES10: Security update for Apache 2
| [65510] SLES9: Security update for Apache 2
| [65249] SLES9: Security update for Apache 2
| [65230] SLES9: Security update for Apache 2
| [65228] SLES9: Security update for Apache 2
| [65207] SLES9: Security update for Apache 2
| [65136] SLES9: Security update for Apache 2
| [65017] SLES9: Security update for Apache 2
|
| SecurityTracker - https://www.securitytracker.com:
| [1008196] Apache 2.x on Windows May Return Unexpected Files For URLs Ending With Certain Characters
| [1007143] Apache 2.0 Web Server May Use a Weaker Encryption Implementation Than Specified in Some Cases
| [1006444] Apache 2.0 Web Server Line Feed Buffer Allocation Flaw Lets Remote Users Deny Service
| [1005963] Apache Web Server 2.x Windows Device Access Flaw Lets Remote Users Crash the Server or Possibly Execute Arbitrary Code
| [1004770] Apache 2.x Web Server ap_log_rerror() Function May Disclose Full Installation Path to Remote Users
|
| OSVDB - http://www.osvdb.org:
| [20897] PHP w/ Apache 2 SAPI virtual() Function Unspecified INI Setting Disclosure
|_
|_http-server-header: Apache/2.4.25 (Debian)
8081/tcp open  http    Apache httpd 2.4.25 ((Debian))
| vulscan: VulDB - https://vuldb.com:
| [160579] Apache Cassandra up to 2.1.21/2.2.17/3.0.21/3.11.7/4.0-beta1 RMI Registry exposure of resource
| [121358] Apache Spark up to 2.1.2/2.2.1/2.3.0 PySpark/SparkR information disclosure
| [113146] Apache CouchDB 2.0.0 Windows Installer nssm.exe access control
| [99052] Apache Ambari up to 2.3.x kadmin information disclosure
| [87539] Apache Ambari up to 2.1.1 Agent data access control
| [79073] Apache Ambari up to 2.0 Config File Password information disclosure
| [79072] Apache Ambari up to 2.0 Config Screen Password information disclosure
| [60632] Debian apache2 2.2.16-6/2.2.22-1/2.22-3 mod_php cross site scripting
| [55501] Apache Mod Fcgid up to 2.3.2 mod_fcgid fcgid_bucket.c fcgid_header_bucket_read numeric error
| [23524] Apache James 2.2.0 Foundation retrieve memory leak
|
| MITRE CVE - https://cve.mitre.org:
| [CVE-2012-0883] envvars (aka envvars-std) in the Apache HTTP Server before 2.4.2 places a zero-length directory name in the LD_LIBRARY_PATH, which allows local users to gain privileges via a Trojan horse DSO in the current working directory during execution of apachectl.
| [CVE-2013-2249] mod_session_dbd.c in the mod_session_dbd module in the Apache HTTP Server before 2.4.5 proceeds with save operations for a session without considering the dirty flag and the requirement for a new session ID, which has unspecified impact and remote attack vectors.
| [CVE-2012-4558] Multiple cross-site scripting (XSS) vulnerabilities in the balancer_handler function in the manager interface in mod_proxy_balancer.c in the mod_proxy_balancer module in the Apache HTTP Server 2.2.x before 2.2.24-dev and 2.4.x before 2.4.4 allow remote attackers to inject arbitrary web script or HTML via a crafted string.
| [CVE-2012-3502] The proxy functionality in (1) mod_proxy_ajp.c in the mod_proxy_ajp module and (2) mod_proxy_http.c in the mod_proxy_http module in the Apache HTTP Server 2.4.x before 2.4.3 does not properly determine the situations that require closing a back-end connection, which allows remote attackers to obtain sensitive information in opportunistic circumstances by reading a response that was intended for a different client.
| [CVE-2012-3499] Multiple cross-site scripting (XSS) vulnerabilities in the Apache HTTP Server 2.2.x before 2.2.24-dev and 2.4.x before 2.4.4 allow remote attackers to inject arbitrary web script or HTML via vectors involving hostnames and URIs in the (1) mod_imagemap, (2) mod_info, (3) mod_ldap, (4) mod_proxy_ftp, and (5) mod_status modules.
| [CVE-2012-3451] Apache CXF before 2.4.9, 2.5.x before 2.5.5, and 2.6.x before 2.6.2 allows remote attackers to execute unintended web-service operations by sending a header with a SOAP Action String that is inconsistent with the message body.
| [CVE-2012-2687] Multiple cross-site scripting (XSS) vulnerabilities in the make_variant_list function in mod_negotiation.c in the mod_negotiation module in the Apache HTTP Server 2.4.x before 2.4.3, when the MultiViews option is enabled, allow remote attackers to inject arbitrary web script or HTML via a crafted filename that is not properly handled during construction of a variant list.
| [CVE-2012-2379] Apache CXF 2.4.x before 2.4.8, 2.5.x before 2.5.4, and 2.6.x before 2.6.1, when a Supporting Token specifies a child WS-SecurityPolicy 1.1 or 1.2 policy, does not properly ensure that an XML element is signed or encrypted, which has unspecified impact and attack vectors.
| [CVE-2012-2378] Apache CXF 2.4.5 through 2.4.7, 2.5.1 through 2.5.3, and 2.6.x before 2.6.1, does not properly enforce child policies of a WS-SecurityPolicy 1.1 SupportingToken policy on the client side, which allows remote attackers to bypass the (1) AlgorithmSuite, (2) SignedParts, (3) SignedElements, (4) EncryptedParts, and (5) EncryptedElements policies.
| [CVE-2011-2516] Off-by-one error in the XML signature feature in Apache XML Security for C++ 1.6.0, as used in Shibboleth before 2.4.3 and possibly other products, allows remote attackers to cause a denial of service (crash) via a signature using a large RSA key, which triggers a buffer overflow.
|
| SecurityFocus - https://www.securityfocus.com/bid/:
| [42102] Apache 'mod_proxy_http' 2.2.9 for Unix Timeout Handling Information Disclosure Vulnerability
| [27237] Apache HTTP Server 2.2.6, 2.0.61 and 1.3.39 'mod_status' Cross-Site Scripting Vulnerability
| [15413] PHP Apache 2 Virtual() Safe_Mode and Open_Basedir Restriction Bypass Vulnerability
| [15177] PHP Apache 2 Local Denial of Service Vulnerability
| [6065] Apache 2 WebDAV CGI POST Request Information Disclosure Vulnerability
| [5816] Apache 2 mod_dav Denial Of Service Vulnerability
| [5486] Apache 2.0 CGI Path Disclosure Vulnerability
| [5485] Apache 2.0 Path Disclosure Vulnerability
| [5434] Apache 2.0 Encoded Backslash Directory Traversal Vulnerability
| [5256] Apache httpd 2.0 CGI Error Path Disclosure Vulnerability
| [4057] Apache 2 for Windows OPTIONS request Path Disclosure Vulnerability
| [4056] Apache 2 for Windows php.exe Path Disclosure Vulnerability
|
| IBM X-Force - https://exchange.xforce.ibmcloud.com:
| [75211] Debian GNU/Linux apache 2 cross-site scripting
|
| Exploit-DB - https://www.exploit-db.com:
| [31052] Apache <= 2.2.6 'mod_negotiation' HTML Injection and HTTP Response Splitting Vulnerability
| [30901] Apache HTTP Server 2.2.6 Windows Share PHP File Extension Mapping Information Disclosure Vulnerability
| [30835] Apache HTTP Server <= 2.2.4 413 Error HTTP Request Method Cross-Site Scripting Weakness
| [28424] Apache 2.x HTTP Server Arbitrary HTTP Request Headers Security Weakness
| [28365] Apache 2.2.2 CGI Script Source Code Information Disclosure Vulnerability
| [27915] Apache James 2.2 SMTP Denial of Service Vulnerability
| [27135] Apache Struts 2 DefaultActionMapper Prefixes OGNL Code Execution
| [26710] Apache CXF prior to 2.5.10, 2.6.7 and 2.7.4 - Denial of Service
| [24590] Apache 2.0.x mod_ssl Remote Denial of Service Vulnerability
| [23581] Apache 2.0.4x mod_perl Module File Descriptor Leakage Vulnerability
| [23482] Apache 2.0.4x mod_php Module File Descriptor Leakage Vulnerability (2)
| [23481] Apache 2.0.4x mod_php Module File Descriptor Leakage Vulnerability (1)
| [23296] Red Hat Apache 2.0.40 Directory Index Default Configuration Error
| [23282] apache cocoon 2.14/2.2 - Directory Traversal vulnerability
| [22191] Apache Web Server 2.0.x MS-DOS Device Name Denial of Service Vulnerability
| [21854] Apache 2.0.39/40 Oversized STDERR Buffer Denial of Service Vulnerability
| [21719] Apache 2.0 Path Disclosure Vulnerability
| [21697] Apache 2.0 Encoded Backslash Directory Traversal Vulnerability
| [20272] Apache 1.2.5/1.3.1,UnityMail 2.0 MIME Header DoS Vulnerability
| [19828] Cobalt RaQ 2.0/3.0 Apache .htaccess Disclosure Vulnerability
| [18984] Apache Struts <= 2.2.1.1 - Remote Command Execution
| [18329] Apache Struts2 <= 2.3.1 - Multiple Vulnerabilities
| [17691] Apache Struts < 2.2.0 - Remote Command Execution
| [15319] Apache 2.2 (Windows) Local Denial of Service
| [14617] Apache JackRabbit 2.0.0 webapp XPath Injection
| [11650] Apache 2.2.14 mod_isapi Dangling Pointer Remote SYSTEM Exploit
| [8458] Apache Geronimo <= 2.1.3 - Multiple Directory Traversal Vulnerabilities
| [5330] Apache 2.0 mod_jk2 2.0.2 - Remote Buffer Overflow Exploit (win32)
| [3996] Apache 2.0.58 mod_rewrite Remote Overflow Exploit (win2k3)
| [2237] Apache < 1.3.37, 2.0.59, 2.2.3 (mod_rewrite) Remote Overflow PoC
| [1056] Apache <= 2.0.49 Arbitrary Long HTTP Headers Denial of Service
| [855] Apache <= 2.0.52 HTTP GET request Denial of Service Exploit
| [132] Apache 1.3.x - 2.0.48 - mod_userdir Remote Users Disclosure Exploit
| [38] Apache <= 2.0.45 APR Remote Exploit -Apache-Knacker.pl
| [34] Webfroot Shoutbox < 2.32 (Apache) Remote Exploit
| [11] Apache <= 2.0.44 Linux Remote Denial of Service Exploit
| [9] Apache HTTP Server 2.x Memory Leak Exploit
|
| OpenVAS (Nessus) - http://www.openvas.org:
| [855524] Solaris Update for Apache 2 120544-14
| [855077] Solaris Update for Apache 2 120543-14
| [100858] Apache 'mod_proxy_http' 2.2.9 for Unix Timeout Handling Information Disclosure Vulnerability
| [72626] Debian Security Advisory DSA 2579-1 (apache2)
| [71551] Gentoo Security Advisory GLSA 201206-25 (apache)
| [71550] Gentoo Security Advisory GLSA 201206-24 (apache tomcat)
| [71485] Debian Security Advisory DSA 2506-1 (libapache-mod-security)
| [71256] Debian Security Advisory DSA 2452-1 (apache2)
| [71238] Debian Security Advisory DSA 2436-1 (libapache2-mod-fcgid)
| [70724] Debian Security Advisory DSA 2405-1 (apache2)
| [70235] Debian Security Advisory DSA 2298-2 (apache2)
| [70233] Debian Security Advisory DSA 2298-1 (apache2)
| [69988] Debian Security Advisory DSA 2279-1 (libapache2-mod-authnz-external)
| [69338] Debian Security Advisory DSA 2202-1 (apache2)
| [65131] SLES9: Security update for Apache 2 oes/CORE
| [64426] Gentoo Security Advisory GLSA 200907-04 (apache)
| [61381] Gentoo Security Advisory GLSA 200807-06 (apache)
| [60582] Gentoo Security Advisory GLSA 200803-19 (apache)
| [58745] Gentoo Security Advisory GLSA 200711-06 (apache)
| [57851] Gentoo Security Advisory GLSA 200608-01 (apache)
| [56246] Gentoo Security Advisory GLSA 200602-03 (Apache)
| [55392] Gentoo Security Advisory GLSA 200509-12 (Apache)
| [55129] Gentoo Security Advisory GLSA 200508-15 (apache)
| [54739] Gentoo Security Advisory GLSA 200411-18 (apache)
| [54724] Gentoo Security Advisory GLSA 200411-03 (apache)
| [54712] Gentoo Security Advisory GLSA 200410-21 (apache)
| [54689] Gentoo Security Advisory GLSA 200409-33 (net=www/apache)
| [54677] Gentoo Security Advisory GLSA 200409-21 (apache)
| [54610] Gentoo Security Advisory GLSA 200407-03 (Apache)
| [54601] Gentoo Security Advisory GLSA 200406-16 (Apache)
| [54590] Gentoo Security Advisory GLSA 200406-05 (Apache)
| [54582] Gentoo Security Advisory GLSA 200405-22 (Apache)
| [54529] Gentoo Security Advisory GLSA 200403-04 (Apache)
| [54499] Gentoo Security Advisory GLSA 200310-04 (Apache)
| [54498] Gentoo Security Advisory GLSA 200310-03 (Apache)
| [11092] Apache 2.0.39 Win32 directory traversal
| [66081] SLES11: Security update for Apache 2
| [66074] SLES10: Security update for Apache 2
| [66070] SLES9: Security update for Apache 2
| [65893] SLES10: Security update for Apache 2
| [65888] SLES10: Security update for Apache 2
| [65510] SLES9: Security update for Apache 2
| [65249] SLES9: Security update for Apache 2
| [65230] SLES9: Security update for Apache 2
| [65228] SLES9: Security update for Apache 2
| [65207] SLES9: Security update for Apache 2
| [65136] SLES9: Security update for Apache 2
| [65017] SLES9: Security update for Apache 2
|
| SecurityTracker - https://www.securitytracker.com:
| [1008196] Apache 2.x on Windows May Return Unexpected Files For URLs Ending With Certain Characters
| [1007143] Apache 2.0 Web Server May Use a Weaker Encryption Implementation Than Specified in Some Cases
| [1006444] Apache 2.0 Web Server Line Feed Buffer Allocation Flaw Lets Remote Users Deny Service
| [1005963] Apache Web Server 2.x Windows Device Access Flaw Lets Remote Users Crash the Server or Possibly Execute Arbitrary Code
| [1004770] Apache 2.x Web Server ap_log_rerror() Function May Disclose Full Installation Path to Remote Users
|
| OSVDB - http://www.osvdb.org:
| [20897] PHP w/ Apache 2 SAPI virtual() Function Unspecified INI Setting Disclosure
|_
|_http-server-header: Apache/2.4.25 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.28 seconds
```