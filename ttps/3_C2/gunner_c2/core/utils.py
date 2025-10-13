import random
import builtins
import string
import os, sys, subprocess
import readline
import logging
from core.session_handlers import session_manager, sessions
from core.teamserver import operator_manager as op_manage
from core.prompt_manager import prompt_manager
from core import print_override
import re
import readline
import base64

from core.help_menus import (
	commands,
	gunnershell_commands_windows,
	gunnershell_commands_linux,
)

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

tcp_listener_sockets = {}
tls_listener_sockets = {}
http_listener_sockets = {}
https_listener_sockets = {}
portforwards = {}

logger = logging.getLogger(__name__)

class SessionDefender:
	def __init__(self):
		self.is_active = True

		# commands that spawn a new shell / interpreter on Windows
		self.win_dangerous = {
			"powershell", "powershell.exe", "cmd", "cmd.exe",
			"curl", "wget", "telnet",
			"python", "python3", "php", "ruby", "irb", "perl",
			"jshell", "node", "ghci"
		}

		# editors & shells on Linux + same interpreters
		self.linux_dangerous = {
			"bash", "sh", "zsh", "tclsh",
			"less", "more", "nano", "pico", "vi", "vim", "gedit", "atom", "emacs", "telnet"
		} | self.win_dangerous

		# regexes for unclosed quotes/backticks on Linux (backslash escapes)
		self._linux_pairings = [
			(r"(?<!\\)'", "'"),
			(r'(?<!\\)"', '"'),
			(r"(?<!\\)`", "`"),
		]
		# regexes for unclosed quotes on Windows (backtick escapes)
		self._win_pairings = [
			(r"(?<!`)'",  "'"),
			(r'(?<!`)"',  '"'),
			# we drop the backtick‐pairing on Windows to avoid confusion
		]

	def inspect_command(self, os_type: str, cmd: str) -> bool:
		"""
		Return True if the command is safe to send, False if it should be blocked.
		"""

		if not cmd:
			return True

		if not self.is_active:
			return True

		# 1) Unclosed quotes/backticks
		if os_type == "windows":
			pairings = self._win_pairings

		else:
			pairings = self._linux_pairings

		for pattern, char in pairings:
			count = len(re.findall(pattern, cmd))
			if count % 2 != 0:
				logger.debug(f"Blocked command {cmd!r} for unclosed {char}s (found {count})")
				return False

		# 2) Trailing backslash (Linux only)
		if os_type == "linux" and cmd.rstrip().endswith("\\"):
			logger.debug(brightred + f"Blocked command {cmd} on linux agent for ending in a backslash")
			return False

		# 3) Dangerous binaries
		first = cmd.strip().split()[0].lower()
		if os_type == "windows":
			if first in self.win_dangerous:
				return False
		else:
			if first in self.linux_dangerous:
				return False

		# safe
		return True


def gen_session_id():
	return '-'.join(
		''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
		for _ in range(3)
	)

PROMPT_PATTERNS = [
	re.compile(r"^PS [^>]+> ?"),         # PowerShell prompt
	re.compile(r"^[\w\-\@]+[:~\w\/-]*[#$] ?"), # bash/zsh prompt
	re.compile(r"^[A-Za-z]:\\.*> ?"),  #CMD shell prompt
	# add more if you spawn e.g. cmd.exe, fish, etc.
]

WRAPPER_ARTIFACTS = {
	'";',              # the stray semicolon+quote line
	'Write-Output "',  # the trailing half-marker line
}

def normalize_output(raw: str, last_cmd: str) -> str:
	"""
	1) Strip the echoed command
	2) Remove any lines matching known prompts
	3) Drop our leftover wrapper artifacts ("; and Write-Output ")
	4) Trim leading/trailing whitespace
	"""
	lines = raw.splitlines()
	cleaned = []

	for line in lines:
		s = line.strip()

		# 1) drop an exact echo of our command
		if s == last_cmd.strip():
			continue

		# 2) drop any PS/CMD/bash prompts
		if any(pat.match(line) for pat in PROMPT_PATTERNS):
			continue

		# 3) drop any pure wrapper‐artifact lines
		if s in WRAPPER_ARTIFACTS:
			continue

		if re.match(r"^__OP__[^_]+__$", s):
			continue

		cleaned.append(line)

	return "\n".join(cleaned).strip()

def echo(msg: str, to_console, to_op, world_wide, color=False, _raw_printer=print, end="\n"):
	#print_override.set_output_context(to_console=to_console, to_op=to_op, world_wide=world_wide)
	logger.debug(
		"ENTER echo: msg=%r, to_console=%r, to_op=%r, world_wide=%r, color=%r, end=%r",
		msg, to_console, to_op, world_wide, color, end
	)

	notcmd = False
	no_raw_print = False
	if world_wide:
		logger.debug("world_wide path: broadcasting to all operators")
		for ident, obj in op_manage.operators.items():
			logger.debug(" → operator %s: handler=%r", ident, obj.handler)
			sock = obj.handler
			queue = obj.op_queue

			if color:
				msg = color + msg

			if sock:
				try:
					sock.send((msg + end).encode())
					logger.debug("   sent to operator %s", ident)

				except Exception as e:
					logger.exception("   error sending to operator %s: %s", ident, e)

		if "gunneroperatoralert{(::)}" in msg.lower():
			no_raw_print = True
			logger.debug("   suppressing local raw_print due to operator-alert/kick")

		elif "gunneroperatorkick{(::)}" in msg.lower():
			no_raw_print = True
			logger.debug("   suppressing local raw_print due to operator-alert/kick")

		if not color and not no_raw_print:
			_raw_printer("\n" + msg, end=end)

		elif not no_raw_print:
			logger.debug("   raw_printing: %r", msg)
			_raw_printer("\n" + color + msg, end=end)

		for keyword in ("new tcp agent", "new tls agent", "new http agent", "new https agent"):
			if keyword in msg.lower():
				notcmd = True
				logger.debug("   detected keyword %r → will redraw prompt", keyword)
				break

		if notcmd:
			prompt = prompt_manager.get_prompt()
			logger.debug("   redrawing prompt %r", prompt)
			sys.stdout.write(prompt)
			readline.redisplay()
			sys.stdout.flush()

		notcmd = False


	elif to_console:
		logger.debug("to_console path")
		if not color:
			_raw_printer(msg, end=end)

		else:
			_raw_printer(color + msg, end=end)

		for keyword in ("new tcp agent", "new tls agent", "new http agent", "new https agent"):
			if keyword in msg.lower():
				notcmd = True
				break

		if notcmd:
			prompt = prompt_manager.get_prompt()
			sys.stdout.write(prompt)
			readline.redisplay()
			sys.stdout.flush()

		notcmd = False

	elif to_op:
		#logger.debug("SELECTED OPERATOR ELIF PATH")
		logger.debug("to_op path, target operator=%r", to_op)
		operator = op_manage.operators[to_op]
		sock = operator.handler
		queue = operator.op_queue

		if color:
			msg = color + msg

		#logger.debug("SENDING TO OPERATOR OVER SOCKET")
		if sock:
			logger.debug("   sending to operator socket: %r", sock)
			try:
				sock.sendall((msg + end).encode())
				logger.debug("   sendall succeeded")

			except BrokenPipeError as e:
				logger.debug(f"HIT BROKEN PIPE ERROR IN ECHO FUNC: {e}")
				op_manage.operators[to_op].pop()

			except Exception as e:
				logger.debug(f"HIT RANDOM EXCEPTION IN ECHO FUNC SENDING TO OP: {e}")


def list_sessions():
	if not session_manager.sessions:
		print(brightyellow + "[*] No sessions connected.")
		return  # <- stop here so the header/bar isn’t printed

	print(brightgreen + (f"{'SID':<20} {'Alias':<15} {'Transport':<10} {'Hostname':<20} {'User':<25} {'OS':<10} {'Arch':<10}"))
	print(brightgreen +("-" * 110))

	for sid, session in session_manager.sessions.items():
		transport = session.transport
		meta = session.metadata

		hostname = meta.get("hostname", "N/A")
		user = meta.get("user", "N/A")
		os_info = meta.get("os")
		arch = meta.get("arch", "N/A")

		# Resolve alias if set
		alias = "N/A"
		for a, real_sid in session_manager.alias_map.items():
			if real_sid == sid:
				alias = a
				break


		if sid is None or transport is None or hostname is None or user is None or os_info is None or arch is None or alias is None:
			print(brightyellow + "Fetching metadata from agent please wait")
			continue
		else:
			print(brightred + (f"{sid:<20} {alias:<15} {transport:<10} {hostname:<20} {user:<25} {os_info:<10} {arch:<10}"))


def list_listeners():
	if not tcp_listener_sockets and not http_listener_sockets and not tls_listener_sockets and not https_listener_sockets:
		print(brightyellow + "No active listeners.")
	else:
		if http_listener_sockets:
			print(brightgreen + "\n[HTTP Listeners]")
			for name in http_listener_sockets:
				print(brightgreen + (f"- {name}"))

		if https_listener_sockets:
			print(brightgreen + "\n[HTTPS Listeners]")
			for name in https_listener_sockets:
				print(brightgreen + (f"- {name}"))

		if tcp_listener_sockets:
			print(brightgreen + "\n[TCP Listeners]")
			for name in tcp_listener_sockets:
				print(brightgreen + (f"- {name}"))

		if tls_listener_sockets:
			print(brightgreen + "\n[TLS Listeners]")
			for name in tls_listener_sockets:
				print(brightgreen + (f"- {name}"))

def shutdown():
	try:
		for name, sock in tcp_listener_sockets.items():
			try:
				sock.close()
				print(brightyellow + f"Closed TCP {name}")

			except:
				pass

	except Exception:
		pass

	try:
		for name, sock in tls_listener_sockets.items():
			try:
				sock.close()
				print(brightyellow + f"Closed TLS {name}")

			except:
				pass

	except Exception:
		pass

	try:
		for name, httpd in http_listener_sockets.items():
			try:
				httpd.shutdown()
				print(brightyellow + f"Closed HTTP {name}")

			except Exception as e:
				print(brightred + f"[!] Failed to shutdown HTTP {name}: {e}")

	except Exception:
		pass

	try:
		for name, httpd in https_listener_sockets.items():
			try:
				httpd.shutdown()
				print(brightyellow + f"Closed HTTPS {name}")

			except Exception as e:
				print(brightred + f"[!] Failed to shutdown HTTPS {name}: {e}")

	except Exception:
		pass


def async_note(msg, prompt, reprint=False, firstnewline=True, secondnewline=True, blockprompt=False):
	"""
	Prints msg on its own line, then re-draws `prompt`
	and whatever the user has typed so far.
	"""
	buffer = readline.get_line_buffer()

	# 2. Move to new line
	if firstnewline is True:
		sys.stdout.write('\r\n')

	# 3. Print the actual message
	if secondnewline is True:
		sys.stdout.write(msg + '\r\n')

	else:
		sys.stdout.write(msg)

	if blockprompt is True:
		prompt_manager.block_next_prompt = True
		return

	if reprint is False and blockprompt is False:
		readline.redisplay()

	else:

		if buffer is not None and all(nl not in buffer for nl in ("\n", "\r", "\r\n")) and buffer:
			sys.stdout.write(prompt + buffer)

		else:
			sys.stdout.write(prompt)

		# 5. Flush to make sure it appears immediately
		sys.stdout.flush()

def register_forward(rule_id, sid, local_host, local_port, remote_host, remote_port, thread, listener):
	"""
	Register an active port-forward rule.

	Args:
		rule_id (str): Unique identifier for this forward.
		sid (str): Session ID.
		local_host (str): Local host/interface to bind.
		local_port (int): Local port to listen on.
		remote_host (str): Remote host to forward to.
		remote_port (int): Remote port to forward to.
		thread (threading.Thread): Thread handling this forward.
		listener (socket.socket): Listening socket for this forward.
	"""
	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
	portforwards[rule_id] = {
		"sid": display,
		"local_host": local_host,
		"local": local_port,
		"remote": f"{remote_host}:{remote_port}",
		"thread": thread,
		"listener": listener
	}

def unregister_forward(rule_id):
	"""
	Remove and stop a port-forward rule, closing its listener and joining its thread.
	"""
	entry = portforwards.pop(rule_id, None)
	if not entry:
		return

	try:
		entry["listener"].close()

	except:
		pass

	entry["thread"].join(timeout=1)

def list_forwards():
	"""
	Return all currently registered port-forward rules.
	"""
	return portforwards

# ----- helpers -----
def _print_section(title: str, items: dict[str, str]):
	header = title
	underline = "=" * len(header)
	print(brightyellow + f"\n{header}\n{underline}\n")
	for name, desc in items.items():
		print(brightgreen + f"{name:<25} {desc}")
	print()


commands = commands

# -----------------------------------------------------------------------------
# GunnerShell mini–help
# -----------------------------------------------------------------------------
#gunnershell_commands = gunnershell_commands

def print_gunnershell_help(cmd: str=None, to_console=True, op_id=None, gunnerplant=False, os_type: str = "windows"):
	"""Like print_help, but grouped and with two‐level detail."""
	# 1) Top‐level: show grouped summary
	#builtins.print = print_override._orig_print
	print_override.set_output_context(to_console=to_console, to_op=op_id, world_wide=False)
	help_dict = gunnershell_commands_windows if "win" in (os_type or "").lower() else gunnershell_commands_linux

	if cmd is None:
		core_cmds = {
			"help":                     "Help menu",
			"exit":                     "Exit the subshell and return to main prompt",
			"list":                     "List all available modules",
			"gunnerid":                 "Show the current session ID for this GunnerShell.",
			"banner":                   "Clears the screen and displays the GUNNER ASCII-art banner.",
			"sessions":                 "List all current gunner agents",
			"switch":                   "Switch to another session's GunnerShell",
			"shell":                    "Drop into a full interactive shell",
			"modhelp":                  "Show module options for a module",
			"run":                      "Execute module with inline options",
			"search":                   "Filter available modules by keyword or show all",
		}
		if os_type.lower() == "windows":
			fs_cmds = {
				"ls":                       "List files on the remote host",
				"cat":                      "Print contents of a file",
				"type":                     "Alias for cat",
				"cd":                       "Change remote working directory",
				"pwd":                      "Print remote working directory",
				"cp":                       "Copy file from source → destination",
				"mv":                       "Move or rename a file/directory",
				"rmdir":                    "Remove a directory (recursive)",
				"checksum":                 "Compute SHA256 of a file",
				"upload":                   "Upload a file to the session",
				"download":                 "Download a file or directory",
				"del":                      "Delete a file on the remote host",
				"rm":                       "Alias for del",
				"mkdir":                    "Create a directory on the remote host",
				"md":                       "Alias for mkdir",
				"touch":                    "Create or update a file on the remote host",
				"drives":                   "List mounted drives/filesystems",
				"edit":                     "Edit a remote text file in your local editor",
			}
			net_cmds = {
				"netstat":                  "Show sockets and listening ports",
				"ifconfig":                 "List network interfaces",
				"portscan":                 "Scan common TCP ports (with ARP-based host discovery)",
				"portfwd":                  "Manage port-forwards on this session",
				"arp":                      "Display ARP table",
				"hostname":                 "Grab the hostname of the agent",
				"socks":                    "Establish a reverse SOCKS5 proxy through the agent.",
				"resolve":                  "Resolve hostname(s)",
				"nslookup":                 "Alias for resolve",
				"route":                    "Show routing table",
				"getproxy":                 "Show Windows proxy config",
				"ipconfig":                 "Display network interfaces (alias: ifconfig)",
				"ifconfig":                 "Alias for ipconfig",
			}
			sys_cmds = {
				"sysinfo":                  "Display remote system information",
				"ps":                       "List running processes",
				"getuid":                   "Show the current user",
				"whoami":                   "Alias for getuid",
				"getprivs":                 "Enumerate process privileges",
				"groups":                   "List group membership",
				"getav":                    "Detect installed AV/EDR products via PowerShell",
				"defenderoff":              "Disable Windows Defender",
				"amsioff":                  "Disable AMSI in‐memory via obfuscated reflection bypass (Working july 2025)",
				"getpid":                   "Print the remote agent’s process ID",
				"getenv":                   "Retrieve one or more environment variables",
				"exec":                     "Execute an arbitrary OS command",
				"kill":                     "Terminate a process by PID",
				"getsid":                   "Show Windows SID of current token",
				"clearev":                  "Clear all Windows event logs",
				"localtime":                "Display target local date/time",
				"reboot":                   "Reboot the remote host",
				"pgrep":                    "Filter processes by name/pattern",
				"pkill":                    "Terminate processes by name/pattern",
				"suspend":                  "Suspend a process by PID",
				"resume":                   "Resume a suspended process",
				"shutdown":                 "Shut down or reboot the remote host",
				"reg":                      "Windows registry operations (query/get/set/delete)",
				"services":                 "Manage services",
				"netusers":                 "List local user accounts",
				"netgroups":                "List local group accounts",
				"steal_token":              "Steal Windows token and inject stage-1 PowerShell payload",
			}
			ui_cmds = {
				"screenshot":               "Capture remote desktop screenshot",
			}
			lateralmovement_cmds = {
				"winrm":                    "Connect via WinRM to a Windows host and run commands or scripts",
				"netexec":                  "Password spraying utility all in native powershell (Fileless)",
				"nxc":                      "Alias for netexec command",
				"rpcexec":                  "RPC Exec via Scheduled-Task COM API on the target(s)",
				"wmiexec":                  "Execute a command via WMI on the remote host"
			}
			ad_cmds = {
				"getusers":                 "Enumerate all AD users via native PowerShell",
				"getgroups":                "Enumerate all AD groups via native Powershell",
				"getcomputers":             "Enumerate all AD connected computers via native Powershell",
				"getdomaincontrollers":     "Enumerate all AD/Forest connected DCs via native Powershell",
				"getous":                   "Enumerate all OUs in the AD domain via native Powershell",
				"getdcs":                   "Alias for getdomaincontrollers",
				"getgpos":                  "Enumerate Group Policy Objects",
				"getdomain":                "Enumerate the AD domain",
				"gettrusts":                "Enumerate all AD trusts",
				"getforests":               "Enumerate all AD forests",
				"getfsmo":                  "Enumerate FSMO roles in the forest",
				"getpwpolicy":              "Enumerate the domain password policy",
				"getdelegation":            "Enumerate objects with constrained/unconstrained delegation",
				"getadmins":                "Enumerate all domain and enterprise admins.",
				"getspns":                  "Enumerate all accounts with ServicePrincipalNames (Kerberoastable)",
				"kerbrute":                 "Bruteforce everything kerberos"
			}

		elif os_type.lower() == "linux":
			fs_cmds = {
				"ls":                       "List files on the remote host",
				"cat":                      "Print contents of a file",
				"cd":                       "Change remote working directory",
				"pwd":                      "Print remote working directory",
				"cp":                       "Copy file from source → destination",
				"mv":                       "Move or rename a file/directory",
				"rmdir":                    "Remove a directory (recursive)",
				"checksum":                 "Compute SHA256 of a file",
				"rm":                       "Alias for del",
				"mkdir":                    "Create a directory on the remote host",
			}


		# ----- dynamic additions -----
		if gunnerplant and os_type.lower() == "windows":
			core_cmds["bofexec"] = "Execute a BOF from library or path"
			core_cmds["bofhelp"] = "Display the entire BOF library"
			core_cmds["bofcount"] = "Display the number of loaded BOFs"

		# ----- OS-aware sections -----
		if os_type.lower() == "windows":
			_print_section("Core Commands", core_cmds)
			_print_section("File system Commands", fs_cmds)
			_print_section("Network Commands", net_cmds)
			_print_section("System Commands", sys_cmds)
			_print_section("User Interface Commands", ui_cmds)
			_print_section("Lateral Movement Commands", lateralmovement_cmds)
			_print_section("Active Directory Commands", ad_cmds)

		elif os_type.lower() == "linux":
			_print_section("Core Commands", core_cmds)
			_print_section("File system Commands", fs_cmds)

		print(brightyellow + "\nFor detailed help run: help <command> [subcommand]\n")
		return

		"""if gunnerplant:
			core_cmds["bofexec"] = "Execute a BOF from library or path"
			core_cmds["bofhelp"] = "Display the entire BOF library"
			core_cmds["bofcount"] = "Display the number of loaded BOFs"

		# print Core
		print(brightyellow + "\nCore Commands\n=============\n")
		for name, desc in core_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print()
		# print File system
		print(brightyellow + "File system Commands\n=====================\n")
		for name, desc in fs_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print()
		# print networking commands
		print(brightyellow + "\nNetwork Commands\n================\n")
		for name, desc in net_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print()
		print(brightyellow + "System Commands\n===============\n")
		for name, desc in sys_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print()
		print(brightyellow + "\nUser Interface Commands\n=======================\n")
		for name, desc in ui_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print()
		print(brightyellow + "Lateral Movement Commands\n=========================\n")
		for name, desc in lateralmovement_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print()
		print(brightyellow + "Active Directory Commands\n=========================\n")
		for name, desc in ad_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print(brightyellow + "\nFor detailed help run: help <command> [subcommand]\n")
		return"""

	# 2) Single‐level detail: help <cmd>
	if cmd:
		parts = cmd.split()
		if parts[0] in COMMAND_ALIASES:
			parts[0] = COMMAND_ALIASES[parts[0]]
			cmd = " ".join(parts)

	parts = cmd.split()
	if len(parts) == 1:
		c = parts[0]
		entry = help_dict.get(c)
		#entry = gunnershell_commands.get(c)
		if entry is None:
			print(brightyellow + f"No help available for '{c}'.\n")
		elif isinstance(entry, str):
			print(brightgreen + f"{entry}")
		else:
			# nested dict: print the overview
			print(brightgreen + f"{entry.get('_desc')}")
		return

	# 3) Two‐level detail: help <cmd> <subcmd>
	if len(parts) == 2:
		c, sub = parts
		entry = help_dict.get(c)
		#entry = gunnershell_commands.get(c)
		if isinstance(entry, dict) and sub in entry:
			print(brightgreen + f"{entry[sub]}")
		else:
			print(brightyellow + f"No help available for '{c} {sub}'.\n")
		return

	# 4) Too deep
	print(brightyellow +
			"Too deep nesting in help. Only:\n"
			"  help\n"
			"  help <command>\n"
			"  help <command> <subcommand>\n")

COMMAND_ALIASES = {
		"dir":       "ls",
		"nxc":       "netexec",
		"getdcs":    "getdomaincontrollers",
		"nslookup":  "resolve",
		"ifconfig":  "ipconfig",
		"md":        "mkdir",
		"rm":        "del",
}

# 1) Two groups of commands + descriptions
MAIN_SESSION_COMMANDS = {
	"start":       "Start listening for new agents",
	"sessions":    "List all active sessions",
	"alias":       "Assign an alias to a session or an operator",
	"listeners":   "List all active listeners",
	"shell":       "Drop into a full interactive shell",
	"kill":        "Terminate a session",
	"jobs":        "List background jobs",
}

MAIN_CORE_UTILITIES = {
	"generate":    "Generate a stager or payload",
	"exec":        "Execute an arbitrary OS command",
	"download":    "Download a file from a session",
	"upload":      "Upload a file to a session",
	"xfer":        "Manage your transfers",
	"portfwd":     "Manage port‐forwards",
	"search":      "Search available modules or sessions",
	"use":         "Select a module to run",
	"banner":      "Show the GUNNER ASCII banner",
	"shelldefence":"Toggle session‐defender on/off",
	"gunnershell": "Drop into the GunnerShell subshell",
}

MAIN_OPERATOR_COMMANDS = {
	"operators":   "List or query operator consoles & accounts",
	"addop":       "Add a new operator account",
	"delop":       "Delete an operator account",
	"modop":       "Modify an operator account",
	"alert":       "Broadcast a message to all operators",
	"kick":        "Kick an operator off the C2",
}

# ─── modify print_help ─────────────────────────────────────────────────
def print_help(cmd=None, gunnershell=False):
	help_dict = gunnershell_commands_windows if gunnershell else commands

	# If no sub‑arg AND we’re in the main shell, show grouped output
	if cmd is None and not gunnershell:
		print(brightyellow + "\nSession Management Commands\n===========================\n")
		for name, desc in MAIN_SESSION_COMMANDS.items():
			print(brightgreen + f"{name:<15} {desc}")
		print()
		print(brightyellow + "Core Utilities\n==============\n")
		for name, desc in MAIN_CORE_UTILITIES.items():
			print(brightgreen + f"{name:<15} {desc}")
		print()
		print(brightyellow + "Operator Commands\n=================\n")
		for name, desc in MAIN_OPERATOR_COMMANDS.items():
			print(brightgreen + f"{name:<15} {desc}")
		print(brightyellow + "\nUsage: help or help <command> [subcommand]\n")
		return

	# Otherwise, fall back to your existing single/ two‑level help logic…
	if cmd:
		parts = cmd.split()
		if parts[0] in COMMAND_ALIASES:
			parts[0] = COMMAND_ALIASES[parts[0]]
			cmd = " ".join(parts)

	if not cmd:
		return

	parts = cmd.split()
	# Top‐level
	if len(parts) == 1:
		c = parts[0]
		if c not in help_dict:
			print(brightyellow + f"No help available for '{c}'.")
			return

		if isinstance(help_dict[c], str):
			print(brightgreen + f"\n{help_dict[c]}\n")
		else:  # dict
			print(brightgreen + f"\n{help_dict[c]['_desc']}\n")
		return

	# Two‐level (subcommand) help
	if len(parts) == 2:
		c, sub = parts
		if c in help_dict and isinstance(help_dict[c], dict) and sub in help_dict[c]:
			print(brightgreen + f"\n{help_dict[c][sub]}\n")
		else:
			print(brightyellow + f"No help available for '{c} {sub}'.")
		return

	print(brightyellow + "Too deep nesting in help. Only 'help' or 'help <command> [sub]' allowed.")

defender = SessionDefender()