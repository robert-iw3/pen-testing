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

@register("getdomain")
class GetDomainCommand(Command):
	"""Dump current domain properties."""

	@property
	def help(self):
		return "getdomain [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getdomain", add_help=False)
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

		ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {{
	  $outprop = (Get-ADDomain {server_arg} | Format-List *)
	  if ($outprop) {{ Write-Output $outprop }}
	  else {{ Write-Output "Nothing Found" }}
  }} else {{
	  # native LDAP fallback: bind to the domain naming context
	  {root}
	  $dom  = [ADSI]"LDAP://$root"
	  foreach ($p in $dom.Properties.PropertyNames) {{
		  $val = $dom.Properties[$p][0]
		  if ($val) {{ Write-Output "$p`: $val" }}
		  else {{ Write-Output "Nothing Found" }}
	  }}
  }}
}} catch {{
  # On error, repeat the LDAP fallback
  {root}
  $dom  = [ADSI]"LDAP://$root"
  foreach ($p in $dom.Properties.PropertyNames) {{
	  $val = $dom.Properties[$p][0]
	  if ($val) {{ Write-Output "$p`: $val" }}
	  else {{ Write-Output "Nothing Found" }}
  }}
}}
"""

		# encode & dispatch, just like your other commands
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
				return brightred + "[!] Didn't find any OUs!"

			elif "Failed to resolve DC!" in out:
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

			else:
				return out