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

@register("getcomputers")
class GetComputersCommand(Command):
	"""List all computers or dump properties for a single computer."""

	@property
	def help(self):
		return "getcomputers [-n <name>] [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getcomputers", add_help=False)
		parser.add_argument("-n","--name",   dest="computer", required=False, help="Computer SamAccountName to fetch properties for")
		parser.add_argument("-d","--domain", dest="domain",   required=False, help="AD domain name (FQDN) or NetBIOS")
		parser.add_argument("--dc-ip",       dest="dc_ip",    required=False, help="IP address of the Domain Controller")

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			sid      = self.gs.sid,
			computer = opts.computer,
			domain   = opts.domain,
			dc_ip    = opts.dc_ip,
			op_id    = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightred + "[!] No output")

	def logic(self, sid, computer=None, domain=None, dc_ip=None, op_id="console"):
		"""
		getcomputers [-n <computer>] [-d <domain>] [--dc-ip <ip>]
		- No args: lists all SamAccountNames of computer objects.
		- With -n: returns every AD property (Name:Value) for that computer.
		- With -d / --dc-ip: target a specific domain or DC.
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		# Resolve DC name logic (same pattern you used for getusers/getgroups)
		if dc_ip:
			target = dc_ip

		elif domain:
			target = domain

		else:
			target = None

		if target:
			dns_preamble = connection_builder(dc_ip, domain)

			if "ERROR" in dns_preamble:
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

		if target:
			server_arg = "-Server $nb"
			root = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"

		else:
			dns_preamble = ""
			server_arg = ""
			root = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"


		# Build the PowerShell snippet
		if computer:
			# single‐computer, fetch all properties
			ps_body = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {{
	  Get-ADComputer -Identity '{computer}' {server_arg} -Properties * | Format-List *
  }} else {{
	  {root}
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher
	  $searcher.SearchRoot = [ADSI]"LDAP://$root"
	  $searcher.Filter     = "(samAccountName={computer})"
	  $res = $searcher.FindOne()
	  if ($res) {{
		foreach ($p in $res.Properties.PropertyNames) {{
		  $v = $res.Properties[$p][0]
		  Write-Output "$p`: $v"
		}}
	  }}
  }}
}} catch {{
  # fallback identical to above
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter     = "(samAccountName={computer})"
  $res = $searcher.FindOne()
  if ($res) {{
	foreach ($p in $res.Properties.PropertyNames) {{
	  $v = $res.Properties[$p][0]
	  Write-Output "$p`: $v"
	}}
  }}
}}
"""
		else:
			# no filter → list all computer names
			ps_body = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {{
	  $comacct = (Get-ADComputer -Filter * {server_arg} | Select-Object -ExpandProperty SamAccountName)
	  if ($comacct) {{ Write-Output $comacct }}
	  else {{ Write-Output "No Computers Found" }}
  }} else {{
	  {root}
	  $searcher  = New-Object System.DirectoryServices.DirectorySearcher(
		  "LDAP://$root","(objectCategory=computer)"
	  )
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		  $n = $r.Properties["samaccountname"][0]
		  if ($n) {{ Write-Output $n }}
		  else {{ Write-Output "No Computers Found" }}
	  }}
  }}
}} catch {{
  # repeat fallback
  {root}
  $searcher  = New-Object System.DirectoryServices.DirectorySearcher(
	  "LDAP://$root","(objectCategory=computer)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
	  $n = $r.Properties["samaccountname"][0]
	  if ($n) {{ Write-Output $n }}
	  else {{ Write-Output "No Computers Found" }}
  }}
}}
"""

		# Base64‐encode and dispatch
		b64 = base64.b64encode(ps_body.encode('utf-16le')).decode()
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
			if "No Computers Found" in out:
				return brightred + "[!] No computers found!"

			elif "Failed to resolve DC!" in out:
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

			else:
				return out