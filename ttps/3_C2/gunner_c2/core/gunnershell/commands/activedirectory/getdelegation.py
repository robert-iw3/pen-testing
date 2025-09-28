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

@register("getdelegation")
class GetDelegationCommand(Command):
	"""List unconstrained or constrained delegation settings."""

	@property
	def help(self):
		return "getdelegation [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getdelegation", add_help=False)
		parser.add_argument("-d","--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
		parser.add_argument("--dc-ip",      dest="dc_ip",  required=False, help="IP address of the Domain Controller")

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			sid    = self.gs.sid,
			domain = opts.domain,
			dc_ip  = opts.dc_ip,
			op_id  = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightred + "[!] No output")

	def logic(self, sid, domain=None, dc_ip=None, op_id="console"):
		"""
		getdelegation [-d <domain>] [--dc-ip <ip>]
		List all objects (users, computers, service accounts) with unconstrained
		or constrained delegation enabled.
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		target = dc_ip or domain or None
		if target:
			dns_preamble = connection_builder(dc_ip, domain)
			if dns_preamble == "ERROR":
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

			server_arg = "-Server $nb"
			root    = '$ldapPath = "LDAP://$nb"; $root = ([ADSI] $ldapPath).defaultNamingContext'
			unconst = f'$uncon = (Get-ADObject -Filter {{ userAccountControl -band 0x80000 }} {server_arg})'
			const = f'$con = (Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" {server_arg} -Properties msDS-AllowedToDelegateTo)'

		else:
			dns_preamble = ""
			server_arg   = ""
			root = '$root = ([ADSI]"LDAP://RootDSE").defaultNamingContext'
			unconst = f'$uncon = (Get-ADObject -Filter {{ userAccountControl -band 0x80000 }})'
			const = f'$con = (Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo)'

		ps = f"""
{dns_preamble}

try {{
  if (Get-Command Get-ADObject -ErrorAction SilentlyContinue) {{
	  {unconst}
	  
	  {const}
	  
	  if ($con) {{ $svc = $con.Properties['msDS-AllowedToDelegateTo'] -join ',' }}
	  if (($uncon) -or ($con)) {{
		if ($uncon) {{
		  foreach ($r in $uncon.Name) {{
			Write-Output "Unconstrained delegation: $r"
		  }}
		}}
		
		if ($con) {{
		  foreach ($r in $con.Name) {{
			Write-Output "Constrained delegation: $r -> $svc"
		  }}
		}}
	  }}
  }}
  else {{
	  {root}
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(userAccountControl:1.2.840.113556.1.4.803:=8192)")
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		  $n = $r.Properties['cn'][0]
		  if ($n) {{
			Write-Output "Unconstrained delegation: $n"
		  }} else {{ Write-Output "Nothing Found" }}
	  }}
	  
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(msDS-AllowedToDelegateTo=*)")
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		  $n        = $r.Properties['cn'][0]
		  $services = $r.Properties['msDS-AllowedToDelegateTo'] -join ','
		  if (($n) -and ($services)) {{ Write-Output "constrained delegation: $n -> $services" }}
		  else {{ Write-Output "Nothing Found" }}
	  }}
  }}
}} catch {{
	{root}
	  
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(userAccountControl:1.2.840.113556.1.4.803:=8192)")
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		  $n = $r.Properties['cn'][0]
		  if ($n) {{
			Write-Output "Unconstrained delegation: $n"
		  }} else {{ Write-Output "Nothing Found" }}
	  }}

	  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(msDS-AllowedToDelegateTo=*)")
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		  $n        = $r.Properties['cn'][0]
		  $services = $r.Properties['msDS-AllowedToDelegateTo'] -join ','
		  if (($n) -and ($services)) {{ Write-Output "constrained delegation: $n -> $services" }}
		  else {{ Write-Output "Nothing Found" }}
	  }}
  }}
"""

		b64 = base64.b64encode(ps.encode('utf-16le')).decode()
		one_liner = (
		"$ps = [System.Text.Encoding]::Unicode"
		f".GetString([Convert]::FromBase64String(\"{b64}\")); Invoke-Expression $ps"
		)

		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, one_liner, op_id=op_id)
	
		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			return brightred + "[!] Unknown session transport!"

		if out:
			if "Failed to resolve DC!" in out:
				return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
		
			elif "Nothing Found" in out:
				return brightred + "[!] No constrained or unconstrained delegation found!"

			else:
				return out