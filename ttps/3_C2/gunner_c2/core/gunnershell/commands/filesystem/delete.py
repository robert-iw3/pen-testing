from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("rm", "del")
class DeleteCommand(Command):
	"""Delete a file on the remote host: delete <path>"""

	@property
	def help(self):
		return "delete <path>    Remove a file remotely"

	def execute(self, args):
		if len(args) != 1:
			print(brightyellow + "Usage: delete <path>")
			return

		path = args[0]
		path = self.gs.make_abs(path)
		out = self.logic(self.gs.sid, self.gs.os_type, path, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] Delete completed!")

	def logic(self, sid, os_type, path, op_id="console"):
		"""
		Delete a file on the remote host.

		- sid:      the real session ID
		- os_type:  session.metadata.get("os") lower‐cased ("windows" vs. "linux")
		- path:     file to delete

		Returns the raw output from the remote command, or None on error.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			# PowerShell: remove the item
			cmd = f'Remove-Item -LiteralPath "{path}" -Force'

		elif "linux" in os_type:
			cmd = f'rm -f "{path}"'

		else:
			print(brightred + f"[!] Unsupported operating system on {display}")
			return None

		sess = session_manager.sessions.get(sid)

		if not sess:
			print(brightred + f"[!] No such session: {display}")
			return None

		transport = sess.transport.lower()
		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)

		else:
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=1.3, portscan_active=True, op_id=op_id)

		return out or None