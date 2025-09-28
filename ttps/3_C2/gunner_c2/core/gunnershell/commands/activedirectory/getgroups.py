import argparse
import base64
import os
import sys

from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen  = "\001" + Style.BRIGHT + Fore.GREEN  + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred    = "\001" + Style.BRIGHT + Fore.RED    + "\002"

@register("getgroups")
class GetGroupsCommand(Command):
	"""List all groups or dump properties/members for a single group."""

	@property
	def help(self):
		return "getgroups [-g <group>] [-m] [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getgroups", add_help=False)
		parser.add_argument("-g","--group",   dest="group",   required=False, help="AD Group to enumerate")
		parser.add_argument("-m","--members", action="store_true", dest="members", help="List members of the group (requires -g)")
		parser.add_argument("-d","--domain",  dest="domain",  required=False, help="AD domain name (FQDN) or NetBIOS")
		parser.add_argument("--dc-ip",        dest="dc_ip",    required=False, help="IP address of the Domain Controller")

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help)
			return

		if opts.members and not opts.group:
			print(brightyellow + "[*] --members requires -g/--group")
			return

		out = self.logic(
			sid     = self.gs.sid,
			group   = opts.group,
			domain  = opts.domain,
			dc_ip   = opts.dc_ip,
			members = opts.members,
			op_id   = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightred + "[!] No output")

	def logic(self, sid, group=None, domain=None, dc_ip=None, members=None, op_id="console"):
		"""
		getgroups [-f <group>] [-d <domain>] [--dc-ip <ip>]
		- No args: lists all SamAccountNames of groups.
		- With group: returns every AD property (Name: Value) for that group.
		- With domain: target that AD domain.
		- With dc_ip: target that DC by IP (falls back to DNS → NetBIOS).
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		if dc_ip:
			dc_ip = dc_ip

		elif not dc_ip and domain:
			dc_ip = domain

		elif dc_ip and domain:
			dc_ip = domain

		if dc_ip and not domain:
			dns_preamble = f"""
$T = '{dc_ip}'
try {{
	$nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
}} catch {{
	$nb = $T
}}
"""
	
		if dc_ip and domain:
			dns_preamble = f"""

try {{
	$domain = '{domain}'
	try {{
	$nb = (Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$domain" | Sort-Object Priority,Weight | Select-Object -First 1).NameTarget.TrimEnd('.')
	}} catch {{ 
			$T = '{dc_ip}'
			try {{
			$nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
		}} catch {{
			$nb = $T
		}}  
	}}
}} catch {{
	Write-Output "Failed to resolve DC!"
	break
}}
"""
	
		if domain:
			dns_preamble = f"""

$domain = '{domain}'
try {{
$nb = (Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$domain" | Sort-Object Priority,Weight | Select-Object -First 1).NameTarget.TrimEnd('.')
}} catch {{ 
			Write-Output "Failed to resolve DC!"
			break
}}
"""
	
		server_arg = "-Server $nb"

		# Build the PS snippet based on which flags are set
		if dc_ip:
			if group and members:
				ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {{
	  # Use the AD cmdlet if available
	  $acct = (Get-ADGroupMember -Identity '{group}' {server_arg} | Select-Object -ExpandProperty SamAccountName)
	  if ($acct) {{ Write-Output $acct }}
	  else {{ Write-Output "No members found" }}
  }} else {{
	  # LDAP fallback: pull the 'member' attribute and resolve each DN
	  $ldapPath = "LDAP://$nb"
	  $root     = ([ADSI] $ldapPath).defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher
	  $searcher.SearchRoot = [ADSI]"LDAP://$root"
	  $searcher.Filter     = "(samAccountName={group})"
	  $grp = $searcher.FindOne()
	  if ($grp) {{
		foreach ($m in $grp.Properties["member"]) {{
		  $entry = [ADSI]"LDAP://$m"
		  $acct  = $entry.Properties["samAccountName"][0]
		  if ($acct) {{ Write-Output $acct }}
		  else {{ Write-Output "No members found" }}
		}}
	  }}
  }}
}} catch {{
  # On error, repeat the LDAP fallback
  $ldapPath = "LDAP://$nb"
  $root     = ([ADSI] $ldapPath).defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter     = "(samAccountName={group})"
  $grp = $searcher.FindOne()
  if ($grp) {{
	foreach ($m in $grp.Properties["member"]) {{
	  $entry = [ADSI]"LDAP://$m"
	  $acct  = $entry.Properties["samAccountName"][0]
	  if ($acct) {{ Write-Output $acct }}
	  else {{ Write-Output "No members found" }}
	}}
  }}
}}
"""

			elif group:
				# DC‑IP + filter
				ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {{
	  $outprop = (Get-ADGroup -Identity '{group}' {server_arg} -Properties * | Format-List *)
	  if ($outprop) {{ Write-Output $outprop }}
	  else {{ Write-Output "No members found" }}
  }} else {{
	  $ldapPath = "LDAP://$nb"
	  $root = ([ADSI] $ldapPath).defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher
	  $searcher.SearchRoot = [ADSI]"LDAP://$root"
	  $searcher.Filter = "(samAccountName={group})"
	  $res = $searcher.FindOne()
	  if ($res) {{
		foreach ($p in $res.Properties.PropertyNames) {{
		  $val = $res.Properties[$p][0]
		  if ($p) {{ Write-Output "$p`: $val" }}
		  else {{ Write-Output "No members found" }}
		}}
	  }}
  }}
}} catch {{
  # LDAP fallback again
  $ldapPath = "LDAP://$nb"
  $root = ([ADSI] $ldapPath).defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter = "(samAccountName={group})"
  $res = $searcher.FindOne()
  if ($res) {{
	foreach ($p in $res.Properties.PropertyNames) {{
	  $val = $res.Properties[$p][0]
	  if ($p) {{ Write-Output "$p`: $val" }}
	  else {{ Write-Output "No members found" }}
	}}
  }}
}}
"""
			else:
				# DC‑IP only → list all groups
				ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {{
	  $outprop = (Get-ADGroup -Filter * {server_arg} | Select-Object -ExpandProperty SamAccountName)
	  if ($outprop) {{ Write-Output $outprop }}
	  else {{ Write-Output "No members found" }}
  }} else {{
	  $ldapPath = "LDAP://$nb"
	  $root = ([ADSI] $ldapPath).defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
		  "LDAP://$root", "(objectCategory=group)"
	  )
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {{
		$grp = $r.Properties["samaccountname"][0]
		if ($grp) {{ Write-Output $grp }}
		else {{ Write-Output "No members found" }}
	  }}
  }}
}} catch {{
  # LDAP fallback again
  $ldapPath = "LDAP://$nb"
  $root = ([ADSI] $ldapPath).defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
	  "LDAP://$root", "(objectCategory=group)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
	$grp = $r.Properties["samaccountname"][0]
	if ($grp) {{ Write-Output $grp }}
	else {{ Write-Output "No members found" }}
  }}
}}
"""

		else:
			# no dc_ip → default RootDSE
			if group and members:
				ps = f"""
try {{
  if (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {{
	  # Use the AD cmdlet if available
	  $acct = (Get-ADGroupMember -Identity '{group}' | Select-Object -ExpandProperty SamAccountName)
	  if ($acct) {{ Write-Output $acct }}
	  else {{ Write-Output "No members found" }}
  }} else {{
	  # LDAP fallback: pull the 'member' attribute and resolve each DN
	  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher
	  $searcher.SearchRoot = [ADSI]"LDAP://$root"
	  $searcher.Filter     = "(samAccountName={group})"
	  $grp = $searcher.FindOne()
	  if ($grp) {{
		foreach ($m in $grp.Properties["member"]) {{
		  $entry = [ADSI]"LDAP://$m"
		  $acct  = $entry.Properties["samAccountName"][0]
		  if ($acct) {{ Write-Output $acct }}
		  else {{ Write-Output "No members found" }}
		}}
	  }}
  }}
}} catch {{
  # On error, repeat the LDAP fallback
  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter     = "(samAccountName={group})"
  $grp = $searcher.FindOne()
  if ($grp) {{
	foreach ($m in $grp.Properties["member"]) {{
	  $entry = [ADSI]"LDAP://$m"
	  $acct  = $entry.Properties["samAccountName"][0]
	  if ($acct) {{ Write-Output $acct }}
	  else {{ Write-Output "No members found" }}
	}}
  }}
}}
"""

			elif group:
				# filter only
				ps = f"""
try {{
  if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {{
	  $outprop = (Get-ADGroup -Identity '{group}' -Properties * | Format-List *)
	  if ($outprop) {{ Write-Output $outprop }}
	  else {{ Write-Output "No members found" }}
  }} else {{
	  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher
	  $searcher.SearchRoot = [ADSI]"LDAP://$root"
	  $searcher.Filter = "(samAccountName={group})"
	  $res = $searcher.FindOne()
	  if ($res) {{
		foreach ($p in $res.Properties.PropertyNames) {{
		  $val = $res.Properties[$p][0]
		  if ($p) {{ Write-Output "$p`: $val" }}
		  else {{ Write-Output "No members found" }}
		}}
	  }}
  }}
}} catch {{
  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter = "(samAccountName={group})"
  $res = $searcher.FindOne()
  if ($res) {{
	foreach ($p in $res.Properties.PropertyNames) {{
	  $val = $res.Properties[$p][0]
	  if ($p) {{ Write-Output "$p`: $val" }}
	  else {{ Write-Output "No members found" }}
	}}
  }}
}}
"""
			else:
				# neither → list all
				ps = """
try {
  if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {
	  $outprop = (Get-ADGroup -Filter * | Select-Object -ExpandProperty SamAccountName)
	  if ($outprop) { Write-Output $outprop }
	  else { Write-Output "No members found" }
  } else {
	  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
		  "LDAP://$root", "(objectCategory=group)"
	  )
	  $searcher.PageSize = 1000
	  $results = $searcher.FindAll()
	  foreach ($r in $results) {
		$grp = $r.Properties["samaccountname"][0]
		if ($grp) { Write-Output $grp }
		else { Write-Output "No members found" }
	  }
  }
} catch {
  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
	  "LDAP://$root", "(objectCategory=group)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {
	$grp = $r.Properties["samaccountname"][0]
	if ($grp) { Write-Output $grp }
	else { Write-Output "No members found" }
  }
}
"""

		# Encode to Base64 UTF‑16LE one‑liner
		b64 = base64.b64encode(ps.encode('utf-16le')).decode()
		one_liner = (
			"$ps = [System.Text.Encoding]::Unicode"
			f".GetString([Convert]::FromBase64String(\"{b64}\")); "
			"Invoke-Expression $ps"
		)

		# Dispatch
		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, one_liner, op_id=op_id)

		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			return brightred + "[!] Unknown session transport!"

		if out:
			if "Failed to resolve DC!" in out:
				return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

			elif "No members found" in out and group:
				return brightred + f"[!] No members in {group}"

			else:
				return out