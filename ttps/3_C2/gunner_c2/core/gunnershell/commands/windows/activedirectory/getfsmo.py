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

@register("getfsmo")
class GetFSMOCommand(Command):
	"""Show forest‐ or domain‐level FSMO role holders."""

	@property
	def help(self):
		return "getfsmo [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getfsmo", add_help=False)
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
		getfsmo [-d <domain>] [--dc-ip <ip>]
		- No flags: shows the forest‑level FSMO role holders (SchemaMaster, DomainNamingMaster).
		- -d, --domain: shows the domain‑level FSMO role holders (PDCEmulator, RIDMaster, InfrastructureMaster).
		- --dc-ip:     target a specific DC by IP (falls back to DNS → NetBIOS).
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		# pick a DC to talk to
		target = dc_ip or domain or None
		if target:
			dns_preamble = connection_builder(dc_ip, domain)
			if dns_preamble == "ERROR":
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"
			server_arg = "-Server $nb"
		else:
			dns_preamble = ""
			server_arg   = ""

		# forest‑level vs domain‑level
		if domain or dc_ip:
			# domain‑level FSMO
			ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {{
	  # AD module
	  $outprop = (Get-ADDomain {server_arg} | Select-Object PDCEmulator,RIDMaster,InfrastructureMaster |
		Format-Table -AutoSize)
	  if ($outprop) {{ Write-Output $outprop }}
	  else {{ Write-Output "Nothing Found" }}
  }} else {{
	  # native LDAP fallback: read fSMORoleOwner from the domain NC head
	  $rootDSE = [ADSI]"LDAP://RootDSE"
	  $dn = $rootDSE.defaultNamingContext
	  $dom = [ADSI]"LDAP://$dn"
	  if ($dom) {{
		Write-Output ("PDCEmulator: "       + $dom.Properties["fSMORoleOwner"][0])
		Write-Output ("RIDMaster: "         + $dom.Properties["fSMORoleOwner"][1])
		Write-Output ("InfrastructureMaster: " + $dom.Properties["fSMORoleOwner"][2])
	  }} else {{ Write-Output "Nothing Found" }}
  }}
}} catch {{
  # on error, repeat native LDAP fallback
  $rootDSE = [ADSI]"LDAP://RootDSE"
  $dn = $rootDSE.defaultNamingContext
  $dom = [ADSI]"LDAP://$dn"
  if ($dom) {{
	Write-Output ("PDCEmulator: "       + $dom.Properties["fSMORoleOwner"][0])
	Write-Output ("RIDMaster: "         + $dom.Properties["fSMORoleOwner"][1])
	Write-Output ("InfrastructureMaster: " + $dom.Properties["fSMORoleOwner"][2])
  }} else {{ Write-Output "Nothing Found" }}
}}
"""
		else:
			# forest‑level FSMO
			ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADForest -ErrorAction SilentlyContinue) {{
	  # AD module
	  $outprop = (Get-ADForest {server_arg} | Select-Object SchemaMaster,DomainNamingMaster |
		Format-Table -AutoSize)
	  if ($outprop) {{ Write-Output $outprop }}
	  else {{ Write-Output "Nothing Found" }}
  }} else {{
	  # native LDAP fallback: read fSMORoleOwner from each NC head
	  $rootDSE = [ADSI]"LDAP://RootDSE"
	  $schemaNC = $rootDSE.schemaNamingContext
	  $configNC = $rootDSE.configurationNamingContext
	  $schema = [ADSI]"LDAP://$schemaNC"
	  $config = [ADSI]"LDAP://$configNC"
	  if ($config -and $schema) {{
		Write-Output ("SchemaMaster: "        + $schema.Properties["fSMORoleOwner"][0])
		Write-Output ("DomainNamingMaster: " + $config.Properties["fSMORoleOwner"][0]) 
	  }} else {{ Write-Output "Nothing Found" }}   
  }}
}} catch {{
  # on error, repeat native LDAP fallback
  $rootDSE = [ADSI]"LDAP://RootDSE"
  $schemaNC = $rootDSE.schemaNamingContext
  $configNC = $rootDSE.configurationNamingContext
  $schema = [ADSI]"LDAP://$schemaNC"
  $config = [ADSI]"LDAP://$configNC"
  if ($config -and $schema) {{
	Write-Output ("SchemaMaster: "        + $schema.Properties["fSMORoleOwner"][0])
	Write-Output ("DomainNamingMaster: " + $config.Properties["fSMORoleOwner"][0]) 
  }} else {{ Write-Output "Nothing Found" }}
}}
"""

		# Base64‑encode & dispatch
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
			if "Failed to resolve DC!" in out:
				return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
		
			elif "Nothing Found" in out:
				return brightred + "[!] No trust relationships found!"

			else:
				return out