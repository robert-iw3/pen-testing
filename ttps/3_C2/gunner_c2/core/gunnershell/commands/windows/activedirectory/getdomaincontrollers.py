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

@register("getdomaincontrollers", "getdcs")
class GetDomainControllersCommand(Command):
	"""List all DCs in the current domain or across the forest."""

	@property
	def help(self):
		return "getdomaincontrollers [-d <domain>] [--dc-ip <ip>] [-e, --enterprise]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getdomaincontrollers", add_help=False)
		parser.add_argument("-d","--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
		parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")
		parser.add_argument("-e","--enterprise", action="store_true", dest="enterprise", help="Enumerate DCs across the entire forest")

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			sid        = self.gs.sid,
			domain     = opts.domain,
			dc_ip      = opts.dc_ip,
			enterprise = opts.enterprise,
			op_id      = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightred + "[!] No output")

	def logic(self, sid, domain=None, dc_ip=None, enterprise=False, op_id="console"):
		"""
		getdomaincontrollers [-d <domain>] [--dc-ip <ip>] [-e, --enterprise]
		- No flags: lists all DC hostnames in the current domain.
		- -d/--dc-ip: target a specific domain or DC.
		- -e/--enterprise: enumerate DCs in every domain in the forest.
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		# figure out target for single-domain queries
		target = dc_ip or domain or None

		# preamble to resolve a single DC host
		if target:
			preamble = connection_builder(dc_ip, domain)
			if "ERROR" in preamble:
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

	
		if target:
			server_arg = "-Server $nb"
			if enterprise:
				root = "$ldapPath = \"LDAP://$nb\"; $forestRoot = ([ADSI] $ldapPath).configurationNamingContext"

			root = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"

		else:
			preamble = ""
			server_arg = ""
			if enterprise:
				root = "$forestRoot = ([ADSI]\"LDAP://RootDSE\").configurationNamingContext"

			root = "([ADSI]\"LDAP://RootDSE\").defaultNamingContext"

		# build the main PS snippet
		if enterprise:
			ps = f"""
{preamble}
try {{
  if (Get-Command Get-ADForest -ErrorAction SilentlyContinue) {{
	  $forest = Get-ADForest {server_arg}
	  foreach ($d in $forest.Domains) {{
		  $results = (Get-ADDomainController -Filter * -Server $d | Select-Object @{{ Name='HostName'; Expression={{ $_.HostName }} }})
		  foreach ($r in $results) {{
			if ($r) {{ Write-Output $r }}
			else {{ Write-Output "Nothing Found" }}
		  }}
	  }}
  }}
  else {{
	  
	  {root}
	  $searcher   = New-Object System.DirectoryServices.DirectorySearcher(
		  "LDAP://$forestRoot",
		  "(objectCategory=server)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
	  )
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		$n = $r.Properties["dNSHostName"][0]
		if ($n) {{ Write-Output $n }}
		else {{ Write-Output "Nothing Found" }}
	  }}
  }}
}}
catch {{
  
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
	  "LDAP://$forestRoot",
	  "(objectCategory=server)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
	$n = $r.Properties["dNSHostName"][0]
	if ($n) {{ Write-Output $n }}
	else {{ Write-Output "Nothing Found" }}
  }}
}}
"""

		else:
			ps = f"""
{preamble}
try {{
  if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {{
	  $controlacct = (Get-ADDomainController {server_arg} -Filter * | Select-Object -ExpandProperty HostName)
	  if ($controlacct) {{ Write-Output $controlacct }}
	  else {{ Write-Output "Nothing Found" }}
  }} else {{
	  {root}
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(objectCategory=server)(userAccountControl:1.2.840.113556.1.4.803:=8192)")
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		$n = $r.Properties["dNSHostName"][0]
		if ($n) {{ Write-Output $n }}
		else {{ Write-Output "Nothing found" }}
	  }}
  }}
}} catch {{
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(objectCategory=server)(userAccountControl:1.2.840.113556.1.4.803:=8192)")
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
	$n = $r.Properties["dNSHostName"][0]
	if ($n) {{ Write-Output $n }}
	else {{ Write-Output "Nothing found" }}
  }}
}}
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

		if out:
			if "Nothing Found" in out:
				return brightred + "[!] Couldn't find any domain controllers!"

			elif "Failed to resolve DC!" in out:
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

			else:
				return out