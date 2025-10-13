from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"

@register("pgrep")
class PgrepCommand(Command):
	"""Filter processes by pattern: pgrep <pattern>"""

	@property
	def help(self):
		return "pgrep <pattern>    Filter remote processes"

	def execute(self, args):
		if len(args) != 1:
			print(brightyellow + "Usage: pgrep <pattern>")
			return
		out = self.logic(self.gs.sid, self.gs.os_type, args[0], op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, pattern, op_id="console"):
		"""
		Filter processes by name/pattern.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if not pattern:
			return brightyellow + "[*] Usage: pgrep <pattern>"

		if "windows" in os_type:
			cmd = (
				"Get-Process | "
				f"Where-Object {{ $_.ProcessName -match '{pattern}' }} | "
				"Select-Object Id,ProcessName | "
				"Format-Table -AutoSize"
			)

		else:
			cmd = f"pgrep -fl '{pattern}'"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)

		else:
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		return out or None