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

@register("gettrusts")
class GetTrustsCommand(Command):
	"""List or dump AD trust relationships."""

	@property
	def help(self):
		return "gettrusts [-d <domain>] [--dc-ip <ip>] [-n <name>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="gettrusts", add_help=False)
		parser.add_argument("-d","--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
		parser.add_argument("--dc-ip",      dest="dc_ip",  required=False, help="IP address of the Domain Controller")
		parser.add_argument("-n","--name",   dest="name",   required=False, help="Name of a single trust to dump properties for")

		try:
			opts = parser.parse_args(args)

		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			sid    = self.gs.sid,
			domain = opts.domain,
			dc_ip  = opts.dc_ip,
			name   = opts.name,
			op_id  = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightred + "[!] No output")

	def logic(self, sid, domain=None, dc_ip=None, name=None, op_id="console"):
		"""
		gettrusts [-d <domain>] [--dc-ip <ip>]
		- No flags: lists all trust relationships for the current domain.
		- With -d/--domain or --dc-ip: target that domain/DC.
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		# decide which DC to target
		target = dc_ip or domain or None
		if target:
			dns_preamble = connection_builder(dc_ip, domain)
			if dns_preamble == "ERROR":
				return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
			server_arg = "-Server $nb"
			root = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"
		else:
			dns_preamble = ""
			server_arg   = ""
			root = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"

		# build the PS snippet
		if name:
			ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {{
	  # AD module path
	  $outprop = (Get-ADTrust -Identity '{name}' {server_arg} | Format-List *)
	  if ($outprop) {{ Write-Output $outprop }}
	  else {{ Write-Output "Nothing Found" }}
  }} else {{
	  # LDAP fallback for a single trustedDomain
	  {root}
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
		  "LDAP://CN=System,$root",
		  "(cn={name})"
	  )
	  $res = $searcher.FindOne()
	  if ($res) {{
		foreach ($p in $res.Properties.PropertyNames) {{
		  $v = $res.Properties[$p][0]
		  if ($p) {{ Write-Output "$p`: $v" }}
		  else {{ Write-Output "Nothing Found" }}
		}}
	  }}
  }}
}} catch {{
  # on error, repeat LDAP fallback
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
	  "LDAP://CN=System,$root",
	  "(cn={name})"
  )
  $res = $searcher.FindOne()
  if ($res) {{
	foreach ($p in $res.Properties.PropertyNames) {{
	  $v = $res.Properties[$p][0]
	  if ($p) {{ Write-Output "$p`: $v" }}
	  else {{ Write-Output "Nothing Found" }}
	}}
  }}
}}
"""

		else:
			ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {{
	  # use the AD module
	  $outprop = (Get-ADTrust {server_arg} -Filter * | Select-Object Name,TrustType,Direction,TargetName)
	  if ($outprop) {{ Write-Output $outprop }}
	  else {{ Write-Output "Nothing Found" }}
  }} else {{
	  # native LDAP fallback: look under CN=System for trustedDomain objects
	  {root}
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
		  "LDAP://CN=System,$root",
		  "(objectClass=trustedDomain)"
	  )
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		$p    = $r.Properties
		$name = $p["cn"][0]
		$type = $p["trustType"][0]
		$dir  = $p["trustDirection"][0]

		if ($p["flatName"] -and $p["flatName"].Count -gt 0) {{
			$tgt = $p["flatName"][0]
		}} else {{
			$tgt = $name
		}}
		if ($p) {{ Write-Output ("{{0}} {{1}} {{2}} → {{3}}" -f $name, $type, $dir, $tgt) }}
		else {{ Write-Output "Nothing Found" }}
	  }}
  }}
}} catch {{
  # on error, repeat the LDAP fallback
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
	  "LDAP://CN=System,$root",
	  "(objectClass=trustedDomain)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
	$p    = $r.Properties
	$name = $p["cn"][0]
	$type = $p["trustType"][0]
	$dir  = $p["trustDirection"][0]

	if ($p["flatName"] -and $p["flatName"].Count -gt 0) {{
			$tgt = $p["flatName"][0]
		}} else {{
			$tgt = $name
		}}

	if ($p) {{ Write-Output ("{{0}} {{1}} {{2}} → {{3}}" -f $name, $type, $dir, $tgt) }}
	else {{ Write-Output "Nothing Found" }}
  }}
}}
"""

		# UTF‑16LE + Base64 encode
		b64 = base64.b64encode(ps.encode('utf-16le')).decode()
		one_liner = (
			"$ps = [System.Text.Encoding]::Unicode"
			f".GetString([Convert]::FromBase64String(\"{b64}\")); "
			"Invoke-Expression $ps"
		)

		# dispatch to the agent
		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, one_liner, op_id=op_id)
	
		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			return brightred + "[!] Unknown session transport!"

		# post‑process exactly like your other commands
		if out:
			if "Failed to resolve DC!" in out:
				return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
		
			elif "Nothing Found" in out:
				return brightred + "[!] No trust relationships found!"

			else:
				return out