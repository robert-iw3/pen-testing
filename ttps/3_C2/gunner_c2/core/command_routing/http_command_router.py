import base64
import queue
import time
import logging
from core.utils import defender, normalize_output

logger = logging.getLogger(__name__)

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

class CommandRouter:
	"""
	Encapsulates per-operator command enqueueing and response dequeueing.
	"""
	def __init__(self, session):
		self.session = session
		logger.debug(
			"[%s] CommandRouter initialized for session %r",
			time.strftime("%Y-%m-%d %H:%M:%S"), session.sid
		)

	def _ensure_queues(self, op_id: str):
		"""
		Make sure both command and response queues exist for this operator.
		"""

		before_cmd = len(self.session.merge_command_queue)
		before_res = len(self.session.merge_response_queue)

		self.session.merge_command_queue.setdefault(op_id, queue.Queue())
		self.session.merge_response_queue.setdefault(op_id, queue.Queue())

		logger.debug(
			"[%s] Queues ensured for op_id=%r (cmd_queues: %d→%d, res_queues: %d→%d)",
			time.strftime("%H:%M:%S"),
			op_id,
			before_cmd, len(self.session.merge_command_queue),
			before_res, len(self.session.merge_response_queue)
		)

	def send(self, cmd: str, op_id: str = "console", defender_bypass: bool = False, transfer_use: bool = False):
		"""
		Apply Session-Defender, base64-encode cmd, then enqueue it.
		Raises PermissionError if defender blocks it.
		"""

		self.cmd = cmd

		start_ts = time.time()
		logger.debug(
			"[%s] send() called: cmd=%r, op_id=%r, defender_bypass=%r",
			time.strftime("%Y-%m-%d %H:%M:%S"), cmd, op_id, defender_bypass
		)

		self._ensure_queues(op_id)

		# Session-Defender check
		logger.debug("[%s] Defender active=%r", time.strftime("%H:%M:%S"), defender.is_active)

		os_type = self.session.metadata.get("os", "").lower()
		if defender.is_active and not defender_bypass:
			if os_type in ("windows", "linux"):
				allowed = defender.inspect_command(os_type, cmd)
				if not allowed:
					logger.debug("Command blocked by Session-Defender")
					raise PermissionError("Command blocked by Session-Defender")

		logger.debug(
			"[%s] Defender check passed for op_id=%r (os_type=%r)",
			time.strftime("%H:%M:%S"), op_id, os_type
		)

		# Base64 encode & enqueue
		b64_cmd = base64.b64encode(cmd.encode()).decode()
		logger.debug(
			"[%s] Encoded cmd to base64 for op_id=%r: %r",
			time.strftime("%H:%M:%S"), op_id, b64_cmd
		)

		try:
			self.session.merge_command_queue[op_id].put(b64_cmd)

		except Exception as e:
			logger.warning(brightred + f"Hit exception while sending in HTTP/HTTPS: {e}" + reset)
			if transfer_use:
				raise ConnectionError("Hit ConnectionError while sending over HTTP/HTTPS") from e

		logger.debug(
			"[%s] Enqueued command for op_id=%r; queue_size=%d",
			time.strftime("%H:%M:%S"),
			op_id,
			self.session.merge_command_queue[op_id].qsize()
		)

		logger.debug(
			"[%s] send() completed in %.4fs", time.strftime("%H:%M:%S"), time.time() - start_ts
		)

	def receive(self, op_id: str = "console", block: bool = True, timeout: float = None, transfer_use: bool = False) -> str:
		"""
		Dequeue a response (base64) for op_id, decode, and return it.
		If block=False, raises queue.Empty on no data.
		"""
		self._ensure_queues(op_id)
		q = self.session.merge_response_queue[op_id]

		logger.debug(
			"[%s] receive() called: op_id=%r, block=%r, timeout=%s, queue_size=%d",
			time.strftime("%H:%M:%S"),
			op_id, block, str(timeout),
			q.qsize()
		)

		if block:
			out_b64 = q.get(timeout=timeout)

		else:
			out_b64 = q.get_nowait()

		try:
			decoded = base64.b64decode(out_b64).decode("utf-8", "ignore").strip()
		except Exception as e:
			logger.warning(
				"[%s] Failed to decode response for op_id=%r: %s",
				time.strftime("%H:%M:%S"), op_id, e
			)
			if transfer_use:
				raise ConnectionError("Hit ConnectionError while reading over HTTP/HTTPS") from e

			return ""

		#logger.debug(f"Decoding base64 output: {out_b64}")

		logger.debug(
			"[%s] Dequeued & decoded response for op_id=%r; remaining_queue=%d: %r",
			time.strftime("%H:%M:%S"),
			op_id,
			self.session.merge_response_queue[op_id].qsize(),
			decoded
		)
		decoded = normalize_output(decoded, self.cmd)
		return decoded

	def flush_response(self, op_id: str = "console"):
		"""
		Drop any pending responses for this op_id.
		"""
		self._ensure_queues(op_id)
		q = self.session.merge_response_queue[op_id]

		logger.debug(
			"[%s] flush_response() called for op_id=%r; starting_queue=%d",
			time.strftime("%H:%M:%S"),
			op_id,
			q.qsize()
		)
		count = 0

		while not q.empty():
			q.get_nowait()
			count += 1

		logger.debug(
			"[%s] flush_response() cleared %d items for op_id=%r; final_queue=%d",
			time.strftime("%H:%M:%S"),
			count, op_id, q.qsize()
		)

	def flush_commands(self, op_id: str = "console"):
		"""
		Drop any pending commands for this op_id.
		"""
		self._ensure_queues(op_id)
		q = self.session.merge_command_queue[op_id]

		logger.debug(
			"[%s] flush_commands() called for op_id=%r; starting_queue=%d",
			time.strftime("%H:%M:%S"),
			op_id,
			q.qsize()
		)
		count = 0

		while not q.empty():
			q.get_nowait()
			count += 1

		logger.debug(
			"[%s] flush_commands() cleared %d items for op_id=%r; final_queue=%d",
			time.strftime("%H:%M:%S"),
			count, op_id, q.qsize()
		)
