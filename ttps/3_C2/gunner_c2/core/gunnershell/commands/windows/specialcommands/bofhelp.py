from __future__ import annotations
import io
import re
from contextlib import redirect_stdout
from typing import List, Tuple

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED   + "\002"
reset       = Style.RESET_ALL

from core.gunnershell.commands.base import register, Command, QuietParser
from core.gunnershell.bofs.base import BOFS, load as load_bof_registry

# ---- Configure which BOFs belong to this section (order preserved) ----
SA_ORDER: List[str] = [
	"whoami",
	"dir",
	# add more situational awareness BOF names here, in the order you want
]

# ---- Helpers to extract a one-liner description from each provider ----
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
CTRL_RE = re.compile(r"[\001\002]")

def _clean(s: str) -> str:
	s = ANSI_RE.sub("", s)
	s = CTRL_RE.sub("", s)
	return s.strip()

def _one_liner_for(name: str):
	"""Prefer first line of docstring; else first non-empty line from help_menu()."""
	cls = BOFS.get(name)
	if not cls:
		return ""

	# Fallback: capture provider's help_menu() output
	help_fn = getattr(cls, "help_menu", None)
	if callable(help_fn):
		try:
			buf = io.StringIO()
			with redirect_stdout(buf):
				out = help_fn()
				if isinstance(out, str) and out.strip():
					print(out)
			for line in _clean(buf.getvalue()).splitlines():
				L = line.strip()
				# Skip generic "Usage:" header lines
				if L and not L.lower().startswith("usage"):
					return L
		except Exception:
			pass
	return ""

def _gather_sa(term: str | None) -> List[Tuple[str, str]]:
	"""Return [(name, desc)] for SA BOFs that exist in registry (optionally filtered)."""
	items: List[Tuple[str, str]] = []
	hay_term = term.lower() if term else None

	for name in SA_ORDER:
		if name not in BOFS:
			# silently skip if not registered
			continue
		desc = _one_liner_for(name)
		if hay_term:
			combined = f"{name} {desc}".lower()
			if hay_term not in combined:
				continue
		items.append((name, desc))
	return items

def print_section(title, items):
	underline = "=" * len(title)
	print(brightyellow + f"{title}\n{underline}\n" + reset)
	for name, desc in items.items():
		print(brightgreen + f"{name:<25} {desc}" + reset)
	print()

@register("bofhelp")
class BOFHelp(Command):
	"""
	bofhelp [TERM] — Lists BOFs in sections like GunnerShell help.
	Currently prints the 'Situational Awareness' section.
	If TERM is provided, results are filtered by that search term.
	"""
	@property
	def help(self):
		return "bofhelp [TERM]  — list BOFs by section (Situational Awareness). If TERM is provided, filter matches."

	def _parse(self, args):
		p = QuietParser(prog="bofhelp", add_help=False)
		p.add_argument("term", nargs="?", default=None, help="optional search term")
		try:
			return p.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help + reset)
			return None

	def execute(self, args):
		ns = self._parse(args)
		if not ns:
			return

		self.logic(ns)
		return

	def logic(self, ns):

		# Ensure registry is available
		if not BOFS:
			load_bof_registry()

		if not ns.term:
			# ---- Situational Awareness section ----
			sa_bofs = {
				"dir":              			   "Display directory contents",
				"env":              			   "Display environment variables",
				"getpwpolicy":      			   "Get server or domain password policy",
				"useridletime":                    "Shows the user's idle time",
				"getsessinfo":      			   "Get local session info",
				"listmods":         			   "List a process's imported DLL's",
				"netlocalgroup":    			   "List local groups/local group members",
				"netloggedon":      			   "List all active user sessions",
				"nettime":          			   "Display local time on agent",
				"netuptime":        			   "Show uptime of machine",
				"netuser":          			   "Enumerate users in the AD domain",
				"netuserenum":      			   "Enumerate users in AD domain or local server",
				"whoami":           		       "Run internal command whoami /all",
				"tasklist":         		       "Lists currently running processes",
				"cacls":            		       "Display file permissions (Wildcards supported!)",
				"enumdrives":                      "Enumerate drive letters and their type",
				"enumdotnet":                      "Find processes that most likely have .NET loaded",
				"sc_enum":          	           "Enumerate all service configs in depth",
				"schtasksenum":     			   "Enumerates all scheduled tasks on the local or target machine",
				"schtasksquery":                   "Lists the details of the requested task",
				"getrecentfiles":                  "Lists recent files for current user",
				"enumlocalsessions":               "Enumerate the currently attached user sessions both local and over rdp",
			}

			system_information_bofs = {
				"winver":                          "Display Windows version info",
				"locale":           			   "Get system locale information",
				"dotnetversion":                   "Enumerates installed .NET versions",
				"listinstalled":                   "Enumerates installed software (x86/x64)",
				"getkernaldrivers":                "Lists loaded kernel drivers",
				"hotfixenum":                      "Lists installed hotfixes & patch level",
				"resources":        		       "Display computer memory information",
				"getgpu":                          "Enumerates Basic GPU & driver info",
				"getcpu":                          "Enumerates basic CPU & driver info",
				"getbios":                         "Reports BIOS and firmware info",

			}

			token_identity_bofs = {
				"getintegrity":                    "Queries the current process token and reports its Windows integrity level",
				"getuac":                          "Determines UAC is enabled and reports it's level",
				"tokenprivs":                      "Checks Available Token Privileges",
			}

			networking_bofs = {
				"arp":              			   "Display ARP table",
				"ipconfig":         			   "Get network information",
				"probe":                           "Check if a port is open",
				"listfwrules":      			   "List all firewall rules",
				"listdns":          			   "List all cached DNS records",
				"netstat":          			   "Show sockets and listening ports",
				"openports":                       "Lists open ports without spawning child processess",
				"routeprint":       		       "Print the entire route table",
				"netview":          	           "Lists local workstations and servers",
				"netshares":        	           "Lists shares on local or remote computer",
			}

			privilege_escalation_bofs = {
				"noquotesvc":                      "Check for unquoted service paths",
				"checkautoruns":                   "Checks For Modifiable Autoruns",
				"hijackpath":                      "Checks For Hijackable Paths",
				"enumcreds":                       "Enumerates Credentials From Credential Manager",
				"enumautologons":                  "Checks for Autologon Registry Keys",
				"checkelevated":                   "Checks for Always Install Elevated Registry Keys",
			}

			credential_dumping_bofs = {
				"hivesave":                        "Dumps registry SAM / SECURITY / SYSTEM to a path of your choosing",
				"hashdump":                        "Dumps local SAM hashes completely in memory",
				"nanodump":                        "Dumps LSASS with syscalls",
				"credman":                         "Dumps credentials from Windows Credential Manager",
				"wifidump":                        "Enumerates WiFi interfaces and dumps clear text credentials",
				"dumpclip":                        "Prints any text on the clipboard",
				"dumpntlm":                        "Capture the NetNTLMv2 hash of the current user",
				"notepad":          		       "Steals text from any active notepad window",
				"autologon":                       "Checks AutoLogon for credentials",
			}

			activedirectory_bofs = {
				"ldapsearch":                      "Executes LDAP query",
				"domaininfo":                      "Domain/forest functional levels + FSMO owners",
				"adadmins":                        "Finds Privileged Users & Privileged Groups",
				"adusers":                         "Enumerates Active Directory users",
				"adgroups":                        "Enumerates Active Directory groups",
				"adcomputers":                     "Enumerates Active Directory computers",
				"adtrusts":                        "Enumerates Active Directory Trusts",
				"adous":                           "Map OU structure and show linked GPOs",
				"adgpos":                          "Enumerates Group Policy Objects (GPOs)",
				"adspns":                          "Enumerates Service Principal Names (SPNs)",
				"addns":                           "The Ultimate AD DNS Enumeration BOF",
				"addelegations":                   "Enumerates unconstrained / constrained delegation and RBCD",
				"adpasswords":                     "Identify Accounts with Interesting/Vulnerable Password Policies",
				"adstaleusers":                    "Enumerates Stale/Inactive Active Directory Users",
				"adcs_enum":                       "Enumerates CAs and templates in the AD using Win32 functions",
				"adcs_enum_com":                   "Enumerates CAs and templates in the AD using ICertConfig COM object",
				"adcs_enum_com2":                  "Enumerates CAs and templates in the AD using IX509PolicyServerListManager COM object",
			}

			activedirectory_aclenum_bofs = {
				"enumacls":                        "Active Directory Attack Path Hunter",
				"dcsyncenum":                      "Finds Dangerous DC sync privileges",
				"enumrbcd":                        "Finds Resource-Based Constrained Delegation",
				"enumgmsa":                        "Finds principals allowed to retrieve gMSA passwords",
			}

			kerberos_bofs = {
				"klist":                           "Displays a list of currently cached Kerberos tickets.",
				"asktgt":                          "Request a Kerberos TGT and optionally inject it into memory",
				"asreproast":                      "Preform Asreproasting in Active Directory",
			}

			persistence_bofs = {
				"adduser":                         "Add a new user to a machine",
				"enablerdp":                       "Enable Remote Desktop on target",
			}

			evasion_bofs = {
				"getexclusions":                   "Check the AV for excluded files, folders, extentions and processes",
				"getsecurity":                     "List security products running on the current or remote host",
				"driversigs":       			   "Enumerate common EDR drivers",
				"getsysmon":                       "Verify if Sysmon is running",
				"dumpsysmonconfig":                "Dumps Sysmon’s live configuration directly from the registry",
				"killsysmon":                      "Silence Sysmon by patching its capability to write ETW events to the log",
				"checkdebuggers":                  "Checks for active debuggers running",
			}

			print()
			for title, items in [
				("Situational Awareness", sa_bofs),
				("System Information", system_information_bofs),
				("Networking", networking_bofs),
				("Privilege Escalation", privilege_escalation_bofs),
				("Credential Dumping", credential_dumping_bofs),
				("Active Directory", activedirectory_bofs),
				("AD ACL Enumeration", activedirectory_aclenum_bofs),
				("Kerberos Exploitation", kerberos_bofs),
				("Token & Identity", token_identity_bofs),
				("Persistence", persistence_bofs),
				("Evasion", evasion_bofs),
			]:
				print_section(title, items)

			print(brightyellow + "\nFor detailed help run: bofhelp <bof>\n" + reset)

		else:
			bofclass = BOFS.get(ns.term)
			if bofclass:
				bofclass.help_menu()
				return

			else:
				print(brightred + f"[!] No Such BOF {ns.term} In BOF Library" + reset)
				return


		"""rows = _gather_sa(ns.term)

		if not rows:
			if ns.term:
				print(brightyellow + f"No BOFs matching '{ns.term}' in Situational Awareness." + reset)
			else:
				print(brightyellow + "No BOFs found in Situational Awareness." + reset)
			print()
			print(brightyellow + "For detailed help run: " + brightgreen + "bofexec <bof> -h" + reset)
			return

		# Align with your help menu: name padded to 25 then description
		for name, desc in rows:
			if desc:
				print(brightgreen + f"{name:<25} " + reset + f"{desc}")
			else:
				print(brightgreen + f"{name:<25} " + reset)

		print()
		print(brightyellow + "For detailed help run: " + brightgreen + "bofexec <bof> -h" + reset)"""
