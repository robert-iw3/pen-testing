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

@register("getav")
class GetavCommand(Command):
	"""Detect AV/EDR products: getav"""

	@property
	def help(self):
		return "getav    Enumerate AV/EDR"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, op_id="console"):
		"""
		Run a PowerShell one‑liner (via SecurityCenter2, registry, services, processes)
		to detect AV/EDR products on Windows. On non‑Windows, just prints a warning.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" not in os_type:
			return brightyellow + "[*] getav only supported on Windows targets"

		ps = f"""
function Get-AV_EDR {{
	try {{
		$avProducts = Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
		if ($avProducts) {{
			Write-Output "`n=== Enumerating AV via SecurityCenter2 ==="
			Write-Output $avProducts
		}} else {{

		}}
	}} catch {{

	}}

	$regPaths = @(
		'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
		'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
	)
	$installed = foreach ($p in $regPaths) {{
		Get-ItemProperty $p -ErrorAction SilentlyContinue |
		  Where-Object {{ $_.DisplayName }} |
		  Select-Object DisplayName, DisplayVersion, Publisher
	}}
	$filters = 'Symantec','McAfee','Defender','Windows Defender','Carbon Black','CrowdStrike',
			   'SentinelOne','Palo Alto','Cylance','FireEye','Trend Micro','Sophos',
			   'Kaspersky','ESET','Avast','AVG'
	$securityApps = $installed | Where-Object {{
		$filters | ForEach-Object {{ $_ }} | Where-Object {{ $installed.DisplayName -like "*$_*" }}
	}}
	if ($securityApps) {{
		Write-Output "`n=== Enumerating Installed Security Products (Registry) ==="
		$securityApps | Sort-Object DisplayName | Format-Table -AutoSize
	}} else {{

	}}

	$svcFilters = 'WinDefend','MsMpSvc','Sense','McAfee','FalconService','SentinelAgent',
				  'PaloAlto','Trend','Sophos','Kaspersky','ekrn','avast','avg'
	$avServices = Get-Service | Where-Object {{
		$svcFilters | ForEach-Object {{ $_ }} | Where-Object {{ $_.Name -match $_ }}
	}} | Select-Object Name, DisplayName, Status
	if ($avServices) {{
		Write-Output "`n=== Enumerating Running Services for AV/EDR ==="
		$avServices | Format-Table -AutoSize
	}} else {{

	}}

	$procNames = 'CarbonBlack','CSFalconService','CrowdStrike','SentinelOne',
				 'CiscoSecureEndpoint','Cybereason','Checkpoint','MsSense','MsMpEng'
	$edrProcs = Get-Process | Where-Object {{ $procNames -contains $_.ProcessName }} |
				Select-Object ProcessName, Id, Path
	if ($edrProcs) {{
		Write-Output "`n=== Enumerating Known EDR Processes ==="
		$edrProcs | Format-Table -AutoSize
	}} else {{
		Write-Output "Nothing Found"
	}}
}}

# Execute
Get-AV_EDR
"""

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		b64 = base64.b64encode(ps.encode('utf-16le')).decode()
		ps = (
		"$ps = [System.Text.Encoding]::Unicode"
		f".GetString([Convert]::FromBase64String(\"{b64}\")); Invoke-Expression $ps"
		)

		transport = sess.transport.lower()

		if transport in ("http","https"):
			out = http_exec.run_command_http(sid, ps, op_id=op_id)

		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, ps, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			return brightred + "[!] Unknown session transport!"

		if out:
			if "Nothing Found" in out:
				return brightred + "[!] No AV/EDR products detected or error"

			else:
				return out