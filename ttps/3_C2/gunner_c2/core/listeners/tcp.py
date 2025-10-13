import logging
logger = logging.getLogger(__name__)

import socket
import ssl
import os
import ipaddress
import tempfile
import datetime
import threading
import time

from core.listeners.base import Listener, register_listener, socket_to_listener, _reg_lock
from core import utils
from core.session_handlers import session_manager
from core import shell
from core.print_override import set_output_context
from core.prompt_manager import prompt_manager

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from colorama import Style, Fore
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightgreen  = "\001" + Style.BRIGHT + Fore.GREEN  + "\002"
brightred    = "\001" + Style.BRIGHT + Fore.RED    + "\002"

PROMPT = brightgreen + "GunnerC2 > " + brightgreen

def _generate_tls_context(listen_ip: str) -> ssl.SSLContext:
	"""
	Create a self-signed TLS context for the given IP.
	"""
	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	subject = issuer = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, u"GunnerC2")
	])
	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(datetime.datetime.utcnow())
		.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
	)
	san = x509.SubjectAlternativeName([
		x509.DNSName("GunnerC2"),
		x509.IPAddress(ipaddress.IPv4Address(listen_ip))
	])
	builder = builder.add_extension(san, critical=False)
	cert = builder.sign(key, hashes.SHA256())

	key_bytes = key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)
	cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

	# write to temp files
	key_file = tempfile.NamedTemporaryFile(delete=False)
	cert_file = tempfile.NamedTemporaryFile(delete=False)
	key_file.write(key_bytes)
	cert_file.write(cert_bytes)
	key_file.close()
	cert_file.close()

	ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
	ctx.verify_mode = ssl.CERT_NONE
	ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
	os.unlink(cert_file.name); os.unlink(key_file.name)
	return ctx

def _collect_tcp_metadata(sid: str):
	"""
	Collect OS and other metadata for a newly-registered TCP session.
	"""
	session = session_manager.sessions[sid]
	sock = session.handler
	try:
		# OS detection
		sock.sendall(b"uname\n")
		sock.settimeout(0.5)
		buf = b""
		while True:
			try:
				chunk = sock.recv(4096)
				if not chunk:
					break
				buf += chunk
			except socket.timeout:
				break
		session.detect_os(buf.decode(errors="ignore").strip())
		session.mode = "metadata"

		# metadata commands
		for field, cmd in session.os_metadata_commands:
			sock.sendall((cmd + "\n").encode())
			sock.settimeout(0.6)
			buf = b""
			got = False
			while True:
				try:
					chunk = sock.recv(4096)
					if not chunk:
						break
					buf += chunk
					got = True
				except socket.timeout:
					if not got:
						continue
					break
			out = utils.normalize_output(buf.decode(errors="ignore").strip(), cmd)
			lines = [l for l in out.splitlines() if l.strip() not in ("$", "#", ">")]
			clean = lines[1] if len(lines) > 1 else (lines[0] if lines else "")
			session.metadata[field] = clean
		session.mode = "cmd"
	except Exception as e:
		print(brightred + f"[!] Metadata collection failed for {sid}: {e}")


@register_listener("tcp", "tls")
class TcpListener(Listener):
	"""
	Concrete Listener for TCP and TLS transports.
	"""

	def start(self, ip: str, port: int, cert_path=None, key_path=None, is_ssl=None, to_console=True, op_id=None):
		self.ip = ip
		self.port = port
		self.is_ssl = (self.transport == "tls")
		# keep op_id so the worker thread can use it safely
		self.op_id = op_id

		if to_console:
			set_output_context(to_console=True)
			self.print_type = "console"

		elif op_id and op_id != "console":
			set_output_context(to_console=False, to_op=op_id)
			self.print_type = "operator"

		elif not to_console and op_id and op_id == "console":
			set_output_context(to_console=True, to_op=op_id)
			self.print_type = "console"

		elif to_console and op_id and op_id == "console":
			set_output_context(to_console=True, to_op=op_id)
			self.print_type = "console"

		if self.is_ssl:
			if cert_path and key_path:
				if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
					print(brightred + "[!] Specified cert or key file not found. Exiting listener.")
					logger.exception(brightred + "[!] Specified cert or key file not found. Exiting listener.")
					return

				logger.debug(brightyellow + f"Using supplied cert and key file")
				context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
				context.load_cert_chain(certfile=cert_path, keyfile=key_path)
				print(brightgreen + f"[*] Loaded TLS cert: {cert_path}, key: {key_path}")

			else:
				logger.debug(brightyellow + f"Generating self signed cert for TLS Listener")
				context = _generate_tls_context(self.ip)
		else:
			logger.debug(brightyellow + "Setting context to None")
			context = None

		# prepare socket
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			self.server.bind((ip, port))
			self.server.listen(5)

		except OverflowError:
			print(brightred + f"[!] Must pick a port between 0-65535")
			return None

		except OSError:
			print(brightred + f"[!] Specified port is already in use")
			return None

		except Exception as e:
			print(brightred + f"[!] Failed to bind listener {ip}:{port}: {e}")
			return

		# record mapping
		if self.is_ssl:
			with _reg_lock:
				utils.tls_listener_sockets[f"tls-{ip}:{port}"] = self.server
				socket_to_listener[self.server.fileno()] = self.id

		elif not self.is_ssl:
			with _reg_lock:
				utils.tcp_listener_sockets[f"tcp-{ip}:{port}"] = self.server
				socket_to_listener[self.server.fileno()] = self.id

		else:
			print(brightred + f"[!] Unknown listener type detected!")


		msg = f"[+] {'TLS' if self.is_ssl else 'TCP'} listener started on {ip}:{port}"
		print(brightyellow + msg)

		# spawn accept loop
		self._thread = threading.Thread(
			target=self.run_loop,
			args=(self._stop_event, context),
			daemon=True
		)
		self._thread.start()

	def stop(self, timeout: float = None):
		# signal and close
		self._stop_event.set()
		try:
			# remove mapping so nothing else references this socket
			with _reg_lock:
				try:
					if self.is_ssl:
						utils.tls_listener_sockets.pop(f"tls-{self.ip}:{self.port}", None)
					else:
						utils.tcp_listener_sockets.pop(f"tcp-{self.ip}:{self.port}", None)
				except Exception:
					pass
			self.server.close()
		except:
			pass

		if self._thread:
			self._thread.join(timeout)

	def is_alive(self) -> bool:
		return bool(self._thread and self._thread.is_alive())

	def _probe_shell(self, sock) -> bool:
		"""
		Very small, cross-platform liveness check:
		send 'echo __gunner__' and wait briefly for any reply containing the marker.
		If nothing comes back, treat it as a stray connect and drop it.
		"""
		marker = "__gunner__"
		try:
			sock.settimeout(0.8)
			try:
				sock.sendall(f"echo {marker}\n".encode())
			except Exception:
				# try CRLF variant once
				try:
					sock.sendall(f"echo {marker}\r\n".encode())
				except Exception:
					return False

			deadline = time.time() + 0.8
			data = b""
			while time.time() < deadline:
				try:
					chunk = sock.recv(4096)
				except socket.timeout:
					break
				if not chunk:
					break
				data += chunk
				if marker.encode() in data:
					return True
			return False
		finally:
			try:
				sock.settimeout(None)
			except Exception:
				pass

	def run_loop(self, stop_event: threading.Event, context):
		"""
		Accept incoming connections; wrap in SSL if needed;
		register sessions and collect metadata.
		"""
		if self.is_ssl and context:
			ctx = context

		while not stop_event.is_set():
			try:
				client, addr = self.server.accept()
			except OSError:
				break

			# optional SSL handshake
			if self.is_ssl and ctx:
				client.settimeout(0.5)
				try:
					client = ctx.wrap_socket(client, server_side=True, do_handshake_on_connect=True)
				except Exception:
					print(brightred + f"[!] TLS handshake failed from {addr}")
					client.close()
					continue
				client.settimeout(None)

			"""# ---- NEW: liveness probe before we register anything ----
			if not self._probe_shell(client):
				# no echo -> likely a stray connect / port scan
				try: client.close()
				except Exception: pass
				continue"""

			# register only after we’ve seen the echo
			sid = utils.gen_session_id()
			session_manager.register_tcp_session(sid, client, self.is_ssl)
			self.sessions.append(sid)


			transport_notification = ("TLS" if self.is_ssl else "TCP")
			set_output_context(world_wide=True)
			print(brightgreen + f"[+] New {transport_notification} agent: {sid}")
			if self.print_type == "console":
				set_output_context(to_console=True)

			elif self.print_type == "operator":
				set_output_context(to_console=False, to_op=op_id)

			# banner drain
			client.settimeout(0.5)
			try:
				while True:
					junk = client.recv(1024)
					if not junk:
						break
			except:
				pass
			client.settimeout(None)

			# collect metadata in background
			threading.Thread(target=_collect_tcp_metadata, args=(sid,), daemon=True).start()