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

@register("getgpos")
class GetGPOsCommand(Command):
	"""List all GPOs or dump properties for a single GPO."""

	@property
	def help(self):
		return "getgpos [-n <name>] [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getgpos", add_help=False)
		parser.add_argument("-n","--name", dest="name", required=False, help="GPO DisplayName to fetch AD properties for")
		parser.add_argument("-d","--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
		parser.add_argument("--dc-ip",      dest="dc_ip",  required=False, help="IP address of the Domain Controller")

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			sid    = self.gs.sid,
			name   = opts.name,
			domain = opts.domain,
			dc_ip  = opts.dc_ip,
			op_id  = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightred + "[!] No output")

	def logic(self, sid, name=None, domain=None, dc_ip=None, op_id="console"):
		"""
		getgpos [-n <name>] [-d <domain>] [--dc-ip <ip>]
		- No args: lists all GPO DisplayNames.
		- With -n: returns every AD property (Name:Value) for that GPO.
		- With -d/--dc-ip: target a specific domain or DC.
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
			root = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"

		else:
			dns_preamble = ""
			server_arg   = ""
			root = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"
		
		# Build the PS snippet
		if name:
			# fetch properties for one GPO
			ps = f"""
{dns_preamble}
{root}
try {{
	if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {{
		$outprop = (Get-GPO -Name '{name}' {server_arg} | Format-List *)
		if ($outprop) {{ Write-Output $outprop }}
		else {{ Write-Output "Nothing Found" }}
	}} else {{
		# LDAP fallback: search under CN=Policies,CN=System,<root>
		$ldapPath = "LDAP://CN=Policies,CN=System,$root"
		$searcher = New-Object System.DirectoryServices.DirectorySearcher
		$searcher.SearchRoot = [ADSI]"$ldapPath"
		$searcher.Filter = "(displayName={name})"
		$res = $searcher.FindOne()
		if ($res) {{
			foreach ($p in $res.Properties.PropertyNames) {{
				$v = $res.Properties[$p][0]
				if ($v) {{ Write-Output "$p`: $v" }}
				else {{ Write-Output "Nothing Found" }}
			}}
		}}
	}}
}} catch {{
	# retry LDAP fallback on error
	$ldapPath = "LDAP://CN=Policies,CN=System,$root"
	$searcher = New-Object System.DirectoryServices.DirectorySearcher
	$searcher.SearchRoot = [ADSI]"$ldapPath"
	$searcher.Filter     = "(displayName={name})"
	$res = $searcher.FindOne()
	if ($res) {{
		foreach ($p in $res.Properties.PropertyNames) {{
			$v = $res.Properties[$p][0]
			if ($v) {{ Write-Output "$p`: $v" }}
			else {{ Write-Output "Nothing Found" }}
		}}
	}}
}}
"""
		else:
			# list all GPO display names
			ps = f"""
{dns_preamble}
{root}
try {{
	if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {{
		$outprop = (Get-GPO -All {server_arg} | Select-Object -ExpandProperty DisplayName)
		if ($outprop) {{ Write-Output $outprop }}
		else {{ Write-Output "Nothing Found" }}
	}} else {{
		$ldapPath = "LDAP://CN=Policies,CN=System,$root"
		$searcher = New-Object System.DirectoryServices.DirectorySearcher
		$searcher.SearchRoot = [ADSI]"$ldapPath"
		$searcher.PageSize = 1000
		$results = $searcher.FindAll()
		foreach ($r in $results) {{
			$n = $r.Properties["displayName"][0]
			if ($n) {{ Write-Output $n }}
			else {{ Write-Output "Nothing Found" }}
		}}
	}}
}} catch {{
	# retry LDAP fallback on error
	$ldapPath = "LDAP://CN=Policies,CN=System,$root"
	$searcher = New-Object System.DirectoryServices.DirectorySearcher
	$searcher.SearchRoot = [ADSI]"$ldapPath"
	$searcher.PageSize = 1000
	$results = $searcher.FindAll()
	foreach ($r in $results) {{
		$n = $r.Properties["displayName"][0]
		if ($n) {{ Write-Output $n }}
		else {{ Write-Output "Nothing Found" }}
	}}
}}
"""

		# Base64‑encode and dispatch
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
			if "Nothing Found" in out:
				return brightred + "[!] Didn't find any OUs!"

			elif "Failed to resolve DC!" in out:
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

			else:
				return out