from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"

@register("ps")
class PsCommand(Command):
	"""List running processes: ps"""

	@property
	def help(self):
		return "ps    List remote processes"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output or error")

	def logic(self, sid, os_type, op_id="console"):
		"""
		List running processes on the remote host.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			cmd = (
				"Get-CimInstance Win32_Process | "
				"Select-Object "
				"@{n='PID';e={$_.ProcessId}},"
				"@{n='Name';e={$_.Name}},"
				"@{n='User';e={ ($_.GetOwner()).User }},"
				"@{n='CPU(s)';e={[math]::Round(($_.UserModeTime + $_.KernelModeTime)/1e7,1)}},"
				"@{n='Mem(MB)';e={[math]::Round($_.WorkingSetSize/1MB,1)}},"
				"@{n='Handles';e={$_.HandleCount}},"
				"@{n='Threads';e={$_.ThreadCount}},"
				"@{n='Started';e={$_.CreationDate}},"
				"@{n='Path';e={$_.ExecutablePath}} | "
				"Format-Table -AutoSize | "
				"Out-String -Width 4096"
			)

		else:
			cmd = "ps -auxww"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http", "https"):
			return http_exec.run_command_http(sid, cmd, op_id=op_id) or None
		else:
			return tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, portscan_active=True, op_id=op_id) or None