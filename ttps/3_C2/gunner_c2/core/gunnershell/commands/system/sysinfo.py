from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"

@register("sysinfo")
class SysinfoCommand(Command):
	"""Get basic system information: sysinfo"""

	@property
	def help(self):
		return "sysinfo    Get OS, architecture, hostname, user"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output or error")

	def logic(self, sid, os_type, op_id="console"):
		"""
		Get basic system information (OS, architecture, hostname, user).
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			# PowerShell: detailed OS info
			cmd = (
			"Get-CimInstance Win32_OperatingSystem | ForEach-Object { "
			"$os = $_; "
			"$cs = Get-CimInstance Win32_ComputerSystem; "
			"$loggedOnCount = (Get-CimInstance -ClassName Win32_LoggedOnUser | "
						   "Where-Object { $_.Antecedent -match 'LogonId' }).Count; "
			"[PSCustomObject]@{ "
				"CSName         = $cs.Name; "
				"Caption        = $os.Caption; "
				"OSArchitecture = $os.OSArchitecture; "
				"Version        = $os.Version; "
				"BuildNumber    = $os.BuildNumber; "
				"Domain         = $cs.Domain; "
				"LoggedOnUsers  = $loggedOnCount; "
			"} "
			"} | Format-List"
		)
		else:
			# Linux/Unix: kernel, hostname, user
			cmd = "uname -a && hostname && id"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http", "https"):
			return http_exec.run_command_http(sid, cmd, op_id=op_id) or None
		else:
			return tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, portscan_active=True, op_id=op_id) or None