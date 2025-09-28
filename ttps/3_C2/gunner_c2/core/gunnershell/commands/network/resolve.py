from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("resolve", "nslookup")
class ResolveCommand(Command):
	"""Resolve DNS on target: resolve <hostname>"""

	@property
	def help(self):
		return "resolve <host>    DNS lookup on remote"

	def execute(self, args):
		if len(args) != 1:
			print(brightyellow + "Usage: resolve <hostname>")
			return
		out = self.logic(self.gs.sid, self.gs.os_type, args[0], op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, hostname, op_id="console"):
		"""
		Resolve a DNS name on the target.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if "windows" in os_type.lower():
			cmd = f"nslookup {hostname}"

		else:
			cmd = f"getent hosts {hostname} || host {hostname}"
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http","https"):
			return http_exec.run_command_http(sid, cmd, op_id=op_id) or None

		else:
			return tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id) or None