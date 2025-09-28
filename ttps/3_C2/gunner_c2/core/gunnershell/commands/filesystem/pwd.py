from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager
from colorama import Style, Fore

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

@register("pwd")
class PwdCommand(Command):
	"""Print the remote working directory: pwd"""

	@property
	def help(self):
		return "pwd    Print the remote working directory"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output or error")

	def logic(self, sid, os_type, op_id="console"):
		"""
		Print the remote working directory.

		- sid:      the real session ID
		- os_type:  session.metadata.get("os") lower-cased ("windows" vs. "linux")

		Returns the raw output from the remote command.
		"""
		# resolve display name
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		# pick the right command
		if "windows" in os_type:
			# 'cd' via cmd.exe prints the current dir
			cmd = '(Get-Location).Path'

		elif "linux" in os_type:
			cmd = "pwd"

		else:
			print(brightred + f"[!] Unsupported operating system on {display}")
			return ""

		# look up session
		sess = session_manager.sessions.get(sid)
		if not sess:
			print(brightred + f"[!] No such session: {display}")
			return ""

		# send it via HTTP(S) or TCP/TLS
		transport = sess.transport.lower()
		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)

		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			print(brightred + f"[!] Unsupported shell type: {transport}")
			return ""

		if out:
			return out

		else:
			return None