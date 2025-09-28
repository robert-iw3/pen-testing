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

@register("getforests")
class GetForestsCommand(Command):
		"""List trusted forests or dump properties for a single forest."""

		@property
		def help(self):
				return "getforests [-n <name>] [-d <domain>] [--dc-ip <ip>]"

		def execute(self, args):
				parser = argparse.ArgumentParser(prog="getforests", add_help=False)
				parser.add_argument("-n","--name",   dest="name",   required=False, help="Forest DNS name to dump properties for")
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
			getforest [-n <name>] [-d <domain>] [--dc-ip <ip>]
			- No -n: lists all trusted-forest DNS names.
			- With -n: dumps every property (Name:Value) for that forest.
			- -d/--dc-ip: target a specific DC by name or IP.
			"""
			sess = session_manager.sessions.get(sid)
			if not sess:
					return brightred + "[!] Invalid session"
			transport = sess.transport.lower()

			# pick target for SRV/DNS lookup
			target = dc_ip or domain or None

			if target:
					dns_preamble = connection_builder(dc_ip, domain)
					if dns_preamble == "ERROR":
							return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

					server_arg  = "-Server $nb"
					root_dom    = '$ldapPath = "LDAP://$nb"; $root = ([ADSI] $ldapPath).defaultNamingContext'
					root_forest = '$forestRoot = ([ADSI] "LDAP://$nb").configurationNamingContext'

			else:
					dns_preamble = ""
					server_arg  = ""
					root_dom    = '$root = ([ADSI]"LDAP://RootDSE").defaultNamingContext'
					root_forest = '$forestRoot = ([ADSI]"LDAP://RootDSE").configurationNamingContext'

			if name:
					# dump one forest’s properties
					ps = f"""
{dns_preamble}
{root_forest}
try {{
	if (Get-Command Get-ADForest -ErrorAction SilentlyContinue) {{
			$outprop = (Get-ADForest -Identity '{name}' {server_arg} -Properties * | Format-List *)
			if ($outprop) {{ Write-Output $outprop }}
			else {{ Write-Output "Nothing Found" }}
	}} else {{
			$forest = [ADSI]"LDAP://$forestRoot"
			foreach ($p in $forest.Properties.PropertyNames) {{
					$v = $forest.Properties[$p][0]
					if ($v) {{ Write-Output "$p`: $v" }}
					else {{ Write-Output "Nothing Found" }}
			}}
	}}
}} catch {{
	# retry LDAP fallback
	{root_forest}
	$forest = [ADSI]"LDAP://$forestRoot"
	foreach ($p in $forest.Properties.PropertyNames) {{
			$v = $forest.Properties[$p][0]
			if ($v) {{ Write-Output "$p`: $v" }}
			else {{ Write-Output "Nothing Found" }}
	}}
}}
"""
			else:
					# list all forests trusted by this domain
					ps = f"""
{dns_preamble}
{root_dom}
try {{
	if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {{
			$outprop = (Get-ADTrust {server_arg} -Filter "TrustType -eq 'Forest'" | Select-Object -ExpandProperty TargetName)
			if ($outprop) {{ $found = $true; Write-Output $outprop }}
			else {{ Write-Output "Nothing Found" }}
	}} else {{
			$searcher = New-Object System.DirectoryServices.DirectorySearcher(
					"LDAP://$root","(objectClass=trustedDomain)"
			)
			$searcher.PageSize = 1000
			$results = $searcher.FindAll()
			foreach ($r in $results) {{
				$t = $r.Properties["trustType"][0]
				if ($t) {{
					if ($t -eq 3) {{
						$f = $r.Properties["flatName"][0]
						if (-not $f) {{ $f = $r.Properties["cn"][0] }}
						if ($f) {{ $found = $true; Write-Output $f }}
						else {{ Write-Output "Nothing Found" }}
					}}
				}} else {{ Write-Output "Nothing Found" }}
		}}
	}}
}} catch {{
	# retry LDAP fallback
	{root_dom}
	$searcher = New-Object System.DirectoryServices.DirectorySearcher(
			"LDAP://$root","(objectClass=trustedDomain)"
	)
	$searcher.PageSize = 1000
	$results = $searcher.FindAll()
	foreach ($r in $results) {{
		$t = $r.Properties["trustType"][0]
		if ($t) {{
			if ($t -eq 3) {{
				$f = $r.Properties["flatName"][0]
				if (-not $f) {{ $f = $r.Properties["cn"][0] }}
				if ($f) {{ $found = $true; Write-Output $f }}
				else {{ Write-Output "Nothing Found" }}
			}}
		}} else {{ Write-Output "Nothing Found" }}
	}}
}}

if (-not $found) {{ Write-Output "Nothing Found" }}
"""
			# encode & dispatch
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
							return brightred + "[!] No trust relationships found!"

					else:
							return out