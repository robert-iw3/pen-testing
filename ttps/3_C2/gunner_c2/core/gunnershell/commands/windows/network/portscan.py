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
from itertools import chain, cycle
import _thread
from core.session_handlers import session_manager
from core import print_override

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"
reset = Style.RESET_ALL

@register("portscan")
class PortscanCommand(Command):
	"""Scan ports on a target: portscan <target> [skip_ping] [ports]"""

	@property
	def help(self):
		return "portscan <target> [skip_ping] [ports]    Remote port scan"

	def execute(self, args):
		if not args:
			print(brightyellow + "Usage: portscan <target> [skip_ping] [port_spec]")
			return
		target = args[0]
		# execute(): treat "-Pn" or "--skip-ping" as skip
		if len(args) >= 2 and args[1].startswith("-"):
			skip = "--skip-ping" in args[1].lower() or "-pn" in args[1].lower()
			# if they want a custom port list after, shift the args array
			spec = args[2] if len(args)>=3 else None
		else:
			skip = args[1].lower() in ("true","1","yes") if len(args)>=2 else False
			spec = args[2] if len(args)>=3 else None

		out = self.logic(self.gs.sid, self.gs.os_type, target, skip, spec, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, target, skip_ping=False, port_spec=None, op_id="console"):
		COMMON_PORTS_ps1 = """@"
1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,
109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,
259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,
464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,
625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,
777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,
995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,
1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,
1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,
1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,
1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,
1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,
1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,
2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,
2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,
2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,
2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,
3005-3006,3011,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,
3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,
3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,
3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,
4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,
5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,
5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,
5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,
5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5985-5989,5998-6007,6009,
6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,
6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,
7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,
7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,
8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,
8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,
9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,
9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,
10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,
13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,
16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,
20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,
27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,
42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,
50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,
57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389
"@"""

		def chunked(iterable, size):
			for i in range(0, len(iterable), size):
				yield iterable[i:i+size]

		def expand_ports(port_spec_str):
			# remove the @", "@ wrapper and split on commas
			spec = port_spec_str.strip('@"\n')
			if spec == "-":
				return list(range(1, 65_536))

			parts = spec.split(',')
			ports = []
			for p in parts:
				p = p.strip()
				if '-' in p:
					a, b = map(int, p.split('-'))
					ports.extend(range(a, b+1))
				elif p:
					ports.append(int(p))
			return ports

		ALL_PORTS = expand_ports(COMMON_PORTS_ps1)
		BATCH_SIZE = 50
		PORT_BATCHES = list(chunked(ALL_PORTS, BATCH_SIZE))
		spinner = cycle(["|", "/", "-", "\\"])

		def check_target_arp(sid, runner, gw, target, op_id):
			sess    = session_manager.sessions.get(sid)
			transport = getattr(sess, "transport", None).lower()
			# one-time PS to prime gateway ARP and look for the target’s MAC
			ps = f"""
ping -n 1 -w 500 {gw} | Out-Null
$t = arp -a | Select-String "{target}\\s+([0-9A-Fa-f]{{2}}-){{5}}[0-9A-Fa-f]{{2}}"
if ($t) {{ Write-Output "ARP_OK" }}"""

			b64_check = base64.b64encode(ps.encode('utf-16le')).decode()


			check_cmd = (
				"$ps = [System.Text.Encoding]::Unicode"
				f".GetString([Convert]::FromBase64String(\"{b64_check}\")); "
				"Invoke-Expression $ps"
				)

			if transport in ("tcp", "tls"):
				out = tcp_exec.run_command_tcp(sid, check_cmd, timeout=1, portscan_active=True, op_id=op_id)

			elif transport in ("http", "https"):
				out = http_exec.run_command_http(sid, check_cmd, op_id=op_id)

			else:
				print(brightred + f"[!] Unknown transport!")

			if "ARP_OK" in out:
				return "OK"

			else:
				return "NO"


		def portscan(sid, os_type, target, skip_ping=False, port_spec=None, op_id="console"):
			display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
			sess    = session_manager.sessions.get(sid)

			if not sess:
				return brightred + f"[!] No such session: {display}"

			transport = getattr(sess, "transport", None).lower()
			DYNAMIC_LINES = 2
			ESC = "\x1b["

			runner = http_exec.run_command_http if sess.transport.lower() in ("http","https") else tcp_exec.run_command_tcp

			# Windows branch: inline AMSI-bypass + PS function + invocation
			if "windows" in os_type:
				if "/" in target:
					# parse the CIDR, non-strict so .0/24 or .255/32 etc. are OK
					net = ipaddress.ip_network(target, strict=False)

					# for a /32, ip_network.hosts() is empty, so we special-case it
					if net.num_addresses == 1:
						hosts = [str(net.network_address)]
					else:
						# .hosts() skips network & broadcast; yields all usable
						hosts = [str(h) for h in net.hosts()]

				else:
					# single-IP case
					hosts = [target]

				# 2) optional ping filter
				if not skip_ping:
					alive = []
					for ip in hosts:
						check_cmd = f"Test-Connection -Quiet -Count 1 -ComputerName {ip}"
						b64_check = base64.b64encode(check_cmd.encode('utf-16le')).decode()


						check_cmd = (
							"$ps = [System.Text.Encoding]::Unicode"
							f".GetString([Convert]::FromBase64String(\"{b64_check}\")); "
							"Invoke-Expression $ps"
							)
						if transport in ("tcp", "tls"):
							pong = tcp_exec.run_command_tcp(sid, check_cmd, timeout=2, portscan_active=True, op_id=op_id)

						elif transport in ("http", "https"):
							pong = http_exec.run_command_http(sid, check_cmd, op_id=op_id)

						else:
							print(brightred + f"[!] Unknown transport!")

						if pong and pong.strip().lower() == "true":
							alive.append(ip)

					hosts = alive

				results = {}
				total_hosts = len(hosts)
				gw_cmd = "(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway.NextHop } | Select-Object -First 1 -ExpandProperty IPv4DefaultGateway).NextHop"
				b64_gw = base64.b64encode(gw_cmd.encode('utf-16le')).decode()

				# one-liner to decode & invoke
				gw_cmd = (
					"$ps = [System.Text.Encoding]::Unicode"
					f".GetString([Convert]::FromBase64String(\"{b64_gw}\")); "
					"Invoke-Expression $ps"
					)

				if transport in ("http", "https"):
					gw = http_exec.run_command_http(sid, gw_cmd, op_id=op_id)

				elif transport in ("tcp", "tls"):
					gw = tcp_exec.run_command_tcp(sid, gw_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

				else:
					print(brightred + f"[!] Unknown transport!")


				for ip in hosts[:]:
					print(brightyellow + f"\rDiscovering Hosts [{next(spinner)}]", end="", flush=True)
					#sys.stdout.flush()

					arp_ok = False

					arp_out = check_target_arp(sid, runner, gw, ip, op_id)
					if "OK" in arp_out:
						arp_ok = True

					else:
						skip_ip = True
						hosts.remove(ip)
						continue

					# clear that whole line
					print("\r" + " " * 80 + "\r", end="", flush=True)
					#sys.stdout.flush()

					if not arp_ok:
						# skip this host
						continue

					ports   = []
					batches = PORT_BATCHES
					results[ip] = []

					if port_spec:
						# this uses your existing helper to expand "80,443,1000-1100"
						custom_ports = expand_ports(port_spec)
						# rebuild batches
						batches = list(chunked(custom_ports, BATCH_SIZE))

					elif port_spec == "-":
						custom_ports = list(range(1, 65536))
						batches = list(chunked(custom_ports, BATCH_SIZE))

					else:
						batches = PORT_BATCHES  # your precomputed common-1000 list

					nbatch  = len(batches)

					for bidx, batch in enumerate(batches, start=1):
						# build a comma list of just these 50 ports
						ports_csv = ",".join(map(str, batch))
						ps_func = f"""
$Target   = '{ip}'
$TimeoutMs = 100

$gw = (Get-NetIPConfiguration |
	   Where-Object {{ $_.IPv4DefaultGateway.NextHop }} |
	   Select-Object -First 1 -ExpandProperty IPv4DefaultGateway).NextHop

if (-not $gw) {{
	Write-Output "SKIPPING $Target (no default gateway found)"
}} else {{

	ping -n 1 -w 500 $gw | Out-Null
	$gwMatch = arp -a |
			   Select-String "$gw\\s+([0-9A-Fa-f]{{2}}-){{5}}[0-9A-Fa-f]{{2}}" |
			   Select-Object -First 1

	if ($gwMatch) {{
		$gwEntry = $gwMatch.Line.Trim()
	}}

	if ($gwEntry) {{
		$ports = @({ports_csv})
		foreach ($port in $ports) {{
			Write-Output "TESTING port $port"
			$tcp   = New-Object System.Net.Sockets.TcpClient
			$async = $tcp.BeginConnect($Target, $port, $null, $null)
			if ($async.AsyncWaitHandle.WaitOne($TimeoutMs)) {{
				try {{
					$tcp.EndConnect($async)
					Write-Output "PORT $port OPEN"
					Write-Host   "PORT $port OPEN"
				}} catch {{}}
			}}
			$tcp.Close()
		}}
	}} else {{
		Write-Output "SKIPPING $Target (gateway $gw did not answer ARP)"
	}}
}}
"""

						# UTF-16LE + Base64 encode
						b64 = base64.b64encode(ps_func.encode('utf-16le')).decode()

						# one-liner to decode & invoke
						ps_cmd = (
							"$ps = [System.Text.Encoding]::Unicode"
							f".GetString([Convert]::FromBase64String(\"{b64}\")); "
							"Invoke-Expression $ps"
						)

						if transport in ("tcp", "tls"):
							out = tcp_exec.run_command_tcp(sid, ps_cmd, timeout=0.2, portscan_active=True, op_id=op_id)

						elif transport in ("http", "https"):
							out = http_exec.run_command_http(sid, ps_cmd, op_id=op_id)

						else:
							print(brightred + f"[!] Unknown transport!")

						# parse ports
						if out and "SKIPPING" not in out and "skipping" not in out:
							for raw in out.splitlines():
								line = raw.strip()
								m = re.search(r'PORT\s+(\d+)\s+OPEN', line)

								if m != None:
									ports.append(int(m.group(1)))
									#results[ip] = ports

						pct = int(bidx * 100 / nbatch)
						barlen = 20
						filled = int(barlen * pct / 100)
						bar = "#" * filled + "-" * (barlen - filled)
						print(brightyellow + f"\rScanning [{bar}] {pct:3d}% {bidx}/{nbatch} ⟶ {ip}", end="", flush=True)
						#sys.stdout.flush()

					#sys.stdout.write("\n")
					print("\r" + " " * 80 + "\r", end="", flush=True)
					#sys.stdout.flush()
					results[ip] = sorted(set(ports))

				for _ in range(DYNAMIC_LINES):
					# move cursor up one line
					print(f"{ESC}1A", end="")
					# erase entire line
					print(f"{ESC}2K", end="")

				print_override._orig_print("", end="", flush=True)

				output = []
				for host, ports in results.items():
					if not ports:
						continue

					port_str = " ".join(f"{brightgreen}[{p}]{reset}" for p in ports)
					output.append(f"{brightcyan}→{reset} {host}: {port_str}")

				# return all of them at once
				if output:
					return "\n".join(output) or brightyellow + "[*] No open ports found."


			else:
				# UNIX: use nmap as before
				ping_flag = "-Pn" if skip_ping else ""
				cmd = f"nmap {ping_flag} -p {COMMON_PORTS} {target}"
				return runner(sid, cmd, timeout=60) or brightyellow + "[*] No output or scan failed."

		out = portscan(sid, os_type, target, skip_ping=skip_ping, port_spec=port_spec, op_id=op_id)
		return out