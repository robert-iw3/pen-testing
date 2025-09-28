from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("netstat")
class NetstatCommand(Command):
	"""Show network connections: netstat"""

	@property
	def help(self):
		return "netstat    List remote network connections"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output")

	def logic(self, sid, os_type, op_id="console"):
		"""
		Show network connections on the remote host, very similar to Meterpreter's 'netstat'.

		- sid:     the real session ID
		- os_type: session.metadata.get("os") lower‐cased ("windows" vs. "linux")

		Returns the raw output of the appropriate netstat command.
		"""
		# resolve display name
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		# pick the right command
		if "windows" in os_type:
			# -a all, -n numeric, -o include PID
			cmd = "Get-NetTCPConnection | Select-Object @{n='Proto';e={$_.Protocol}},@{n='Local';e={$_.LocalAddress+':'+$_.LocalPort}},@{n='Remote';e={$_.RemoteAddress+':'+$_.RemotePort}},State,@{n='PID';e={$_.OwningProcess}},@{n='Program';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize"
		else:
			# -t tcp, -u udp, -n numeric, -a all, -p show PID/program name, -e extra
			cmd = "netstat -tunape"

		# look up session
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		# dispatch over HTTP(S) or TCP/TLS
		transport = sess.transport.lower()
		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)

		else:
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=5, portscan_active=True, op_id=op_id)

		# ensure we at least return an empty string
		return out or None