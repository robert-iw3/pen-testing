from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager
import base64

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("groups")
class GroupsCommand(Command):
	"""List user groups: groups"""

	@property
	def help(self):
		return "groups    Show remote user groups"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, op_id="console"):
		"""
		On Windows: run 'whoami /groups'
		On Linux:   run 'id -Gn'
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		# choose the right command
		if "windows" in os_type:
			cmd = f"""
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()


$groups = $user.Groups | ForEach-Object {{
	# Translate SID → DOMAIN\\GroupName
	$name = $_.Translate([System.Security.Principal.NTAccount]).Value
	# Make a PSCustomObject so we can sort & format nicely
	[PSCustomObject]@{{
		GroupName = $name
		SID       = $_.Value
	}}
}}

if ($groups) {{
  $groups | Sort-Object GroupName | Format-Table -AutoSize
}}
else {{
	$out = (whoami /groups)
	if ($out) {{ Write-Output $out }} else {{ Write-Output "Nothing Found" }}
}}
"""
		else:
			cmd = "id -Gn"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if os_type == "windows":
			b64 = base64.b64encode(cmd.encode('utf-16le')).decode()
			cmd = (
			"$ps = [System.Text.Encoding]::Unicode"
			f".GetString([Convert]::FromBase64String(\"{b64}\")); Invoke-Expression $ps"
			)


		# dispatch via HTTP or TCP
		transport = sess.transport.lower()
		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)
	
		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			return brightred + "[!] Unknown session transport!"

		if out:
			if "Nothing Found" in out:
				return brightred + "[!] User is not part of any groups!"

			else:
				return out
