from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("getproxy")
class GetproxyCommand(Command):
	"""Show proxy settings: getproxy"""

	@property
	def help(self):
		return "getproxy    Display remote proxy config"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, op_id="console"):
		"""
		Display the current proxy configuration on the remote host.
		- Windows:  netsh winhttp show proxy
		- Linux/macOS: print any HTTP(S)_PROXY vars
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			cmd = "netsh winhttp show proxy"
		else:
			# catch both lowercase and uppercase env vars
			cmd = "env | grep -i proxy || echo No proxy vars set"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http", "https"):
			return http_exec.run_command_http(sid, cmd, op_id=op_id) or None
		else:
			# give a bit longer in case env takes a moment
			return tcp_exec.run_command_tcp(sid, cmd, timeout=1, portscan_active=True, op_id=op_id) or None