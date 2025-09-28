from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("ipconfig", "ifconfig")
class IpconfigCommand(Command):
	"""Show network interfaces: ipconfig"""

	@property
	def help(self):
		return "ipconfig    Display remote interfaces"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output")

	def logic(self, sid, os_type, op_id="console"):
		"""
		Display network interfaces on the remote host:
		- Windows: ipconfig /all
		- Linux/macOS: ifconfig -a
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		# pick command by OS
		if "windows" in os_type:
			cmd = "ipconfig /all"
		else:
			cmd = "ifconfig -a"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		# dispatch over HTTP(S) or TCP/TLS, with a slightly longer timeout on Windows
		if sess.transport.lower() in ("http", "https"):
			return http_exec.run_command_http(sid, cmd, op_id=op_id) or None
		else:
			return tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id) or None