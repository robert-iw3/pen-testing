from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"

@register("suspend")
class SuspendCommand(Command):
	"""Suspend a process: suspend <pid>"""

	@property
	def help(self):
		return "suspend <pid>    Suspend remote process"

	def execute(self, args):
		if len(args) != 1 or not args[0].isdigit():
			print(brightyellow + "Usage: suspend <pid>")
			return
		out = self.logic(self.gs.sid, self.gs.os_type, args[0], op_id=self.op_id)
		print(brightgreen + out if out else brightred + f"[!] Failed to suspend {args[0]}")

	def logic(self, sid, os_type, pid, op_id="console"):
		"""
		Suspend the given PID on the remote host.
		Usage: suspend <pid>
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if not pid_str.isdigit():
			return brightyellow + "[*] Usage: suspend <pid>"

		if "windows" in os_type:
			# if Suspend-Process exists use it, otherwise P/Invoke NtSuspendProcess
			ps_cmd = (
				"if (Get-Command Suspend-Process -ErrorAction SilentlyContinue) { "
				f"Suspend-Process -Id {pid_str} "
				"} else { "
				f"$p=Get-Process -Id {pid_str}; "
				"Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; "
				"public static class PInvoke { "
					"[DllImport(\"ntdll.dll\")] public static extern uint NtSuspendProcess(IntPtr handle); "
				"}' ; "
				"[PInvoke]::NtSuspendProcess($p.Handle) "
				"}"
			)
		else:
			ps_cmd = f"kill -STOP {pid_str}"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http","https"):
			out = http_exec.run_command_http(sid, ps_cmd, op_id=op_id)
		else:
			out = tcp_exec.run_command_tcp(sid, ps_cmd, timeout=2.0, portscan_active=True, op_id=op_id)

		if out == "0":
			return brightgreen + f"[*] PID {pid_str} successfully suspended"

		elif out != "0":
			return out

		else:
			return brightred + f"[!] Failed to suspend process {pid_str}"