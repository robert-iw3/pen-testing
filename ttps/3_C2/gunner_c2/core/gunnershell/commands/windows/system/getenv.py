from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("getenv")
class GetenvCommand(Command):
	"""Retrieve environment variables: getenv [VAR…]"""

	@property
	def help(self):
		return "getenv [VAR…]    Fetch env vars"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, *args, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, *vars, op_id="console"):
		"""
		Retrieve environment variables from the remote host.
		Usage:
			getenv                # fetch all
			getenv VAR1 [VAR2…]   # fetch just those
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			if len(vars) == 0:
				# Correct PowerShell one-liner to dump all env vars as NAME=VALUE
				cmd = 'Get-ChildItem Env: | ForEach-Object { "$($_.Name)=$($_.Value)" }'
			else:
				parts = [f'"{v}=$env:{v}"' for v in vars]
				cmd = "Write-Output " + ", ".join(parts)
		else:
			if len(vars) == 0:
				cmd = "printenv"
			else:
				parts = " ".join(f'"{v}=${v}"' for v in vars)
				cmd = f"sh -c 'printf \"%s\\n\" {parts}'"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http", "https"):
			return http_exec.run_command_http(sid, cmd, op_id=op_id) or None
		else:
			return tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id) or None