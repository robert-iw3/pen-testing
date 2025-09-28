from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("drives")
class DrivesCommand(Command):
	"""List mounted drives/filesystems: drives"""

	@property
	def help(self):
		return "drives    List mounted drives or filesystems"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output or error")

	def logic(self, sid, os_type, op_id="console"):
		"""
		List mounted drives / filesystems on the remote host.

		- sid:      the real session ID
		- os_type:  session.metadata.get("os") lower‐cased ("windows" vs. "linux")

		Returns the raw output from the remote command, or None on error.
		"""
		# resolve display name for errors
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			# PowerShell: only filesystem drives
			cmd = "Get-PSDrive -PSProvider FileSystem | Format-Table Name, Root -AutoSize"

		elif "linux" in os_type:
			# show all mounted filesystems
			cmd = "df -hT"

		else:
			print(brightred + f"[!] Unsupported operating system on {display}")
			return None

		sess = session_manager.sessions.get(sid)
		if not sess:
			print(brightred + f"[!] No such session: {display}")
			return None

		if sess.transport.lower() in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)

		else:
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		return out or None