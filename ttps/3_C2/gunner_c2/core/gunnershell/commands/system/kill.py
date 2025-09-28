from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("kill")
class KillCommand(Command):
	"""Terminate a process: kill <pid>"""

	@property
	def help(self):
		return "kill <pid>    Terminate remote process"

	def execute(self, args):
		if len(args) != 1 or not args[0].isdigit():
			print(brightyellow + "Usage: kill <pid>")
			return
		out = self.logic(self.gs.sid, self.gs.os_type, args[0], op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, pid, op_id="console"):
		"""
		Terminate the given PID on the remote host.
		Usage: kill <pid>
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if not pid_str.isdigit():
			return brightyellow + "[*] Usage: kill <pid>"

		if "windows" in os_type:
			cmd = f"Stop-Process -Id {pid_str} -Force"
		else:
			cmd = f"kill -9 {pid_str}"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http","https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)
		else:
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, portscan_active=True, op_id=op_id)

		if out is None:
			return brightgreen + f"[*] Sent terminate to PID {pid_str}"

		else:
			return out