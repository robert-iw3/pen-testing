import base64
import re
import queue
import socket
import ssl
import threading
import time
import select
import logging

from core.utils import defender
from core import utils

logger = logging.getLogger(__name__)

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

class TcpCommandRouter:
	"""
	Encapsulates per-operator TCP/TLS command execution, response routing, and extreme logging.
	"""
	def __init__(self, session):
		self.session = session
		self.sock = session.handler
		# Marker locks to prevent interleaved sends/receives
		self.send_lock = session.lock
		self.recv_lock = session.recv_lock
		self.exec_lock = session.exec_lock
		self._transfer_use = False
		logger.debug("[%s] TcpCommandRouter initialized for session %r",
					 time.strftime("%Y-%m-%d %H:%M:%S"), session.sid)

	def execute(self,
				cmd: str,
				op_id: str = "console",
				timeout: float = None,
				portscan_active: bool = False,
				retries: int = 0,
				defender_bypass: bool = False,
				transfer_use: bool = False) -> str:
		"""
		Atomically run send+receive under a session-wide lock.
		Ensures two operators never interleave on the same socket.
		"""
		result = ""
		logger.debug(
			"[%s] execute() called: cmd=%r, op_id=%r, timeout=%s, portscan=%r, retries=%d, bypass=%r",
			time.strftime("%Y-%m-%d %H:%M:%S"),
			cmd, op_id, timeout, portscan_active, retries, defender_bypass
		)

		with self.session.exec_lock:
			start_ts = time.time()
			# flush any stray data before we start
			self._drain_socket()

			# send wrapped command
			try:
				self.send(cmd, op_id=op_id, defender_bypass=defender_bypass, transfer_use=transfer_use)
			except Exception as e:
				logger.warning("[%s] execute.send() error: %s", time.strftime("%H:%M:%S"), e)
				if transfer_use:
					raise ConnectionError(f"send failed: {e}") from e


			# receive and normalize
			try:
				result = self.receive(
					cmd=cmd,
					op_id=op_id,
					timeout=timeout,
					portscan_active=portscan_active,
					retries=retries,
					transfer_use=transfer_use,
				)
			except Exception as e:
				logger.warning("[%s] execute.receive() error: %s", time.strftime("%H:%M:%S"), e)
				if transfer_use:
					raise ConnectionError(f"receive failed: {e}") from e


			elapsed = time.time() - start_ts
			logger.debug("[%s] execute() completed in %.4fs, result=%r",
						 time.strftime("%Y-%m-%d %H:%M:%S"), elapsed, result)
			return result


	def _drain_socket(self):
		"""
		Quickly drain any already-queued bytes without blocking.
		Normal 'no data' conditions (EWOULDBLOCK/SSLWantRead) are NOT errors.
		We cap time/bytes so we never spin.
		"""
		logger.debug("[%s] Draining stray bytes before send", time.strftime("%H:%M:%S"))
		drained = 0
		deadline = time.time() + 0.05  # ~50ms budget
		try:
			self.sock.setblocking(False)
			while time.time() < deadline:
				# poll once; if not readable, we’re done
				r, _, _ = select.select([self.sock], [], [], 0)
				if not r:
					break
				try:
					with self.recv_lock:
						chunk = self.sock.recv(8192)
				except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
					# nothing to read right now — not an error
					break
				except (ConnectionResetError, BrokenPipeError, OSError):
					# real socket error: stop draining
					break
				if not chunk:
					# peer closed
					break
				drained += len(chunk)
				if drained > 512 * 1024:  # hard cap ~512KB
					break
		finally:
			# restore blocking/timeout for real work
			self.sock.setblocking(True)
			self.sock.settimeout(self.session.metadata.get("tcp_timeout", 0.5))
		logger.debug("[%s] Drain complete (%d bytes)", time.strftime("%H:%M:%S"), drained)

	def _sh_quote(s: str) -> str:
		# Single-quote for POSIX shells: ' -> '"'"'
		return "'" + (s or "").replace("'", "'\"'\"'") + "'"

	def send(self, cmd: str,
			 op_id: str = "console",
			 defender_bypass: bool = False,
			 transfer_use: bool = False):
		"""
		Wrap command with start/end tokens, apply defender, send over socket.
		Raises PermissionError if blocked by defender.
		"""
		start = f"__OP__{op_id}__"
		end   = f"__ENDOP__{op_id}__"

		logger.debug("[%s] send() called: cmd=%r, op_id=%r, defender_bypass=%r",
					 time.strftime("%Y-%m-%d %H:%M:%S"), cmd, op_id, defender_bypass)

		# Defender check
		os_type = self.session.metadata.get("os", "").lower()
		if defender.is_active and not defender_bypass and os_type in ("windows", "linux"):
			if not defender.inspect_command(os_type, cmd):
				logger.debug("[%s] Command blocked by Session-Defender", time.strftime("%H:%M:%S"))
				#print(brightred + f"Command blocked by Session-Defender" + reset)
				raise PermissionError("Command blocked by Session-Defender")
		logger.debug("[%s] Defender check passed", time.strftime("%H:%M:%S"))

		# Choose shell wrapping
		if os_type == "windows":
			wrapped = f'Write-Output "{start}"; {cmd}; Write-Output "{end}"'

		else:
			wrapped = f"echo {start}; {cmd}; echo {end}"

		logger.debug("[%s] Wrapped command for op_id=%r: %r",
					 time.strftime("%H:%M:%S"), op_id, wrapped)


		self._drain_socket()

		# Send command
		with self.send_lock:
			try:
				self.sock.sendall(wrapped.encode() + b"\n")
				logger.debug("[%s] Sent wrapped command to socket", time.strftime("%H:%M:%S"))

			except (ConnectionResetError, BrokenPipeError, OSError) as e:
				logger.warning(brightred + f"Connect error ocurred on session {self.session.sid}" + reset)
				if transfer_use:
					raise ConnectionError(f"socket send failed: {e}") from e


			except Exception as e:
				logger.warning("[%s] Failed to send command: %s", time.strftime("%H:%M:%S"), e)
				raise


	def receive(self,
				cmd: str,
				op_id: str = "console",
				timeout: float = None,
				portscan_active: bool = False,
				retries: int = 0,
				transfer_use: bool = False) -> str:
		"""
		Read from socket until both start/end tokens for this op_id are seen,
		demux other operators' outputs, normalize and return your slice.
		"""
		start = f"__OP__{op_id}__".encode()
		end   = f"__ENDOP__{op_id}__".encode()

		logger.debug("[%s] receive() called: op_id=%r, timeout=%s, portscan_active=%r, retries=%d",
					 time.strftime("%H:%M:%S"), op_id, timeout, portscan_active, retries)

		# Reader thread to collect bytes
		chunks = []
		got_any = False
		attempt = 0

		def _reader():
			nonlocal got_any, attempt
			while True:
				try:
					with self.recv_lock:
						data = self.sock.recv(4096)
				except socket.timeout:
					if portscan_active and not got_any and (retries == 0 or attempt < retries):
						attempt += 1
						continue
					break

				except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
					# Non-blocking/EAGAIN or TLS wants – nothing ready yet
					time.sleep(0.01)
					continue

				except (ConnectionResetError, BrokenPipeError, OSError):
					logger.debug(brightred + f"Connect error ocurred on session {self.session.sid}" + reset)
					if transfer_use:
						raise ConnectionError("Connection Error in TCP reader function")

					break
				if not data:
					break
				chunks.append(data)
				got_any = True
				if chunks:
					joined = b"".join(chunks)

					if start in joined and end in joined:
						break

		# Set timeout for recv
		with self.send_lock:
			old_to = self.sock.gettimeout()
			self.sock.settimeout(timeout)

		"""try:
			reader = threading.Thread(target=_reader, daemon=True)
			reader.start()
			reader.join(timeout if timeout is not None else None)"""

		try:
			reader = threading.Thread(target=_reader, daemon=True)
			reader.start()

			# Actively wait until we *see* both tokens or we hit the deadline.
			deadline = time.time() + (timeout if timeout is not None else old_to or 0.5)
			while True:
				# Quick local check on what we have so far
				joined = b"".join(chunks)
				if start in joined and end in joined:
					break
				if not reader.is_alive():
					break
				now = time.time()
				if now >= deadline:
					break
				# Don’t burn CPU; give the reader time to append
				time.sleep(0.01)

			# Grace period so the reader can append any final bytes
			reader.join(0.05)

		except (ConnectionResetError, BrokenPipeError, OSError, ConnectionError) as e:
			logger.debug(brightred + f"Connect error ocurred on session {self.session.sid}" + reset)
			if transfer_use:
				raise ConnectionError("Connection Error while reading data over TCP socket")

		# Restore timeout
		with self.send_lock:
			self.sock.settimeout(old_to)

		resp_bytes = b"".join(chunks)
		logger.debug("[%s] Raw response bytes (%d): %r",
					 time.strftime("%H:%M:%S"), len(resp_bytes), resp_bytes)

		# Demux other ops
		pattern = re.compile(rb"__OP__(?P<op>[^_]+)__\s*(?P<out>.*?)\s*__ENDOP__(?P=op)__", re.DOTALL)
		for m in pattern.finditer(resp_bytes):
			o = m.group("op").decode()
			if o == op_id:
				continue

			out = m.group("out").decode(errors="ignore")
			op_que_obj = self.session.merge_response_queue.setdefault(o, queue.Queue())
			q = self.session.merge_response_queue[o]
			q.put(base64.b64encode(out.encode()).decode())
			logger.debug("[%s] Demuxed output for other op %r into queue (size=%d)",
						 time.strftime("%H:%M:%S"), o, q.qsize())

		# Extract our own output
		match = re.search(rf"{re.escape(start.decode())}\s*(.*?)\s*{re.escape(end.decode())}",
						  resp_bytes.decode(errors="ignore"), re.DOTALL)
		if match:
			my_out = match.group(1)
		else:
			# fallback to queue
			try:
				my_out = self.session.merge_response_queue[op_id].get_nowait()
			except queue.Empty:
				logger.debug("[%s] No queued output for op_id=%r", time.strftime("%H:%M:%S"), op_id)
				my_out = ""

		logger.debug("[%s] Raw extracted output for op_id=%r: %r",
					 time.strftime("%H:%M:%S"), op_id, my_out)

		# Normalize
		clean = utils.normalize_output(my_out.strip(), cmd)
		logger.debug("[%s] Normalized output for op_id=%r: %r",
					 time.strftime("%H:%M:%S"), op_id, clean)
		return clean

	def flush_response(self, op_id: str = "console"):
		q = self.session.merge_response_queue.setdefault(op_id, queue.Queue())
		count = 0
		while not q.empty():
			q.get_nowait(); count += 1

		logger.debug("[%s] flush_response cleared %d for op_id=%r",
					 time.strftime("%H:%M:%S"), count, op_id)

	def flush_commands(self, op_id: str = "console"):
		q = self.session.merge_command_queue.setdefault(op_id, queue.Queue())
		count = 0
		while not q.empty():
			q.get_nowait(); count += 1
		logger.debug("[%s] flush_commands cleared %d for op_id=%r",
					 time.strftime("%H:%M:%S"), count, op_id)