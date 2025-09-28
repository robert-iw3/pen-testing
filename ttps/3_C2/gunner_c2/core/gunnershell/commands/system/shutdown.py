from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"

@register("shutdown")
class ShutdownCommand(Command):
	"""Shut down or reboot: shutdown [-r|-h]"""

	@property
	def help(self):
		return "shutdown [-r|-h]    Halt or reboot remote host"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, *args, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, *flags, op_id="console"):
		"""
		Gracefully shut down or power off the remote host.
		Usage: shutdown          # immediate
			   shutdown -r|-h    # reboot (-r) or halt (-h)
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		# decide flags
		flag = args[0].lower() if args else None

		if "windows" in os_type:
			if flag == "-r":
				cmd = "Stop-Computer -Restart -Force"
			elif flag == "-h":
				cmd = "Stop-Computer -Force"
			else:
				cmd = "Stop-Computer -Force"
		else:
			if flag == "-r":
				cmd = "shutdown -r now"
			elif flag == "-h":
				cmd = "shutdown -h now"
			else:
				cmd = "shutdown -h now"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http","https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)
		else:
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=5.0, portscan_active=True, op_id=op_id)

		return out or brightgreen + "[*] Shutdown/reboot issued."