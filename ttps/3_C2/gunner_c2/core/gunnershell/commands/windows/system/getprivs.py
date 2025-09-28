from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("getprivs")
class GetprivsCommand(Command):
	"""Attempt to enable and display process privileges: getprivs"""

	@property
	def help(self):
		return "getprivs    Show process privileges"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output or error")

	def logic(self, sid, os_type, op_id="console"):
		"""
		Attempt to enable and display privileges of the current process.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			cmd = "whoami /priv"
		else:
			# On Linux, show sudo privileges (may prompt or error if not sudo-enabled)
			print(brightyellow + f"[*] Warning this is an interactive command, run sudo -l on an interactive shell instead!")
			#cmd = "sudo -l"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http", "https"):
			return http_exec.run_command_http(sid, cmd, op_id=op_id) or None
		else:
			return tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, portscan_active=True, op_id=op_id) or None
