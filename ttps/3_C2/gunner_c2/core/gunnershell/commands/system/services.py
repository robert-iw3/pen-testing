from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("services")
class ServicesCommand(Command):
	"""List or control services: services <list|start|stop|restart> [name]"""

	@property
	def help(self):
		return "services <list|start|stop|restart> [name]    Manage services"

	def execute(self, args):
		if not args or args[0] not in ("list","start","stop","restart"):
			print(brightyellow + "Usage: services <list|start|stop|restart> [name]")
			return
		action = args[0]
		svc = args[1] if len(args) > 1 else None
		out = self.logic(self.gs.sid, self.gs.os_type, action, svc, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, action=None, svc_name=None, op_id="console"):
		"""
		List or control services on the remote host.
		Usage:
			services list
			services start   <service_name>
			services stop    <service_name>
			services restart <service_name>
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if action not in ("list", "start", "stop", "restart"):
			return brightyellow + "[*] Usage: services <list|start|stop|restart> [<service_name>]"

		# build the command per-action
		if "windows" in os_type:
			if action == "list":
				ps_cmd = "Get-Service | Format-Table -AutoSize | Out-String -Width 4096"
			else:
				verb = {"start": "Start-Service", "stop": "Stop-Service", "restart": "Restart-Service"}[action]
				# Stop-Service accepts -Force, Restart-Service and Start-Service do not
				force_flag = " -Force" if action == "stop" else ""
				ps_cmd = (
					"try { "
					f"{verb} -Name '{svc_name}'{force_flag} -ErrorAction Stop; "
					"Write-Output 'SUCCESS' "
					"} catch { "
					"Write-Output \"FAILED: $($_.Exception.Message)\" "
					"}"
				)
		else:
			if action == "list":
				ps_cmd = "systemctl list-units --type=service --all"

			else:
				# use shell exit code logic for Linux
				ps_cmd = (
					f"systemctl {action} '{svc_name}' "
					"&& echo SUCCESS || echo FAILED: \"Could not {action} {svc_name}\""
				)

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		out = (http_exec.run_command_http(sid, ps_cmd, op_id=op_id)
			if sess.transport.lower() in ("http","https")
			else tcp_exec.run_command_tcp(sid, ps_cmd, timeout=5.0, portscan_active=True, op_id=op_id)
		) or ""

		# handle list
		if action == "list":
			return out or brightyellow + "[*] No services found."

		# for start/stop/restart, parse SUCCESS / FAILED:
		for line in out.splitlines():
			line = line.strip()
			if line == "SUCCESS":
				if action == "stop":
					return brightgreen + f"[*] Service '{svc_name}' Stopped successfully."
				else:
					return brightgreen + f"[*] Service '{svc_name}' {action}ed successfully."

			if line.startswith("FAILED:") or line.startswith("FAILED"):
				return brightred + f"[!] Insufficient privileges to preform {action} on {svc_name} service"

		# fallback if neither token seen
		return brightyellow + "[*] Unexpected output:\n" + out