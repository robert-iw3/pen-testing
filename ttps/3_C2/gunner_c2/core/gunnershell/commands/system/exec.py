from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"

@register("exec")
class ExecCommand(Command):
	"""Execute an arbitrary command: exec <cmd> [args…]"""

	@property
	def help(self):
		return "exec <cmd> [args…]    Run remote command"

	def execute(self, args):
		if not args:
			print(brightyellow + "[*] Usage: exec <cmd> [args…]")
			return
		out = self.logic(self.gs.sid, self.gs.os_type, *args, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, *cmd_parts, op_id="console"):
		"""
		Execute an arbitrary command on the remote host.
		Usage: exec <command> [args...]
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if not cmd_parts:
			return brightyellow + "[*] Usage: exec <command> [args...]"

		# join back into a single command string
		cmd = " ".join(cmd_parts)

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http","https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)
		else:
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		return out or ""