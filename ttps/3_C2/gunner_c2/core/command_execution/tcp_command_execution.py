import queue
import logging

from core.command_routing.tcp_command_router import TcpCommandRouter
from core.session_handlers import session_manager

logger = logging.getLogger(__name__)

def run_command_tcp(sid: str,
					cmd: str,
					timeout: float = 0.5,
					defender_bypass: bool = False,
					portscan_active: bool = False,
					retries: int = 0,
					op_id: str = "console",
					transfer_use: bool = False) -> str | None:
	"""
	Execute `cmd` over a TCP/TLS session identified by `sid`.
	Uses TcpCommandRouter for modular send/receive.
	"""
	session = session_manager.sessions[sid]
	router  = TcpCommandRouter(session)

	# Ensure op_id default
	if not op_id:
		op_id = "console"

	# Flush any stale responses
	router.flush_response(op_id)

	# Atomically sendreceive
	try:
		return router.execute(
			cmd,
			op_id=op_id,
			timeout=timeout,
			portscan_active=portscan_active,
			retries=retries,
			defender_bypass=defender_bypass,
			transfer_use=transfer_use
		)

	except queue.Empty as e:
		logger.debug("TCP execute timeout for sid=%r, op_id=%r", sid, op_id)
		if transfer_use:
			raise ConnectionError(str(e)) from e

	except Exception as e:
		logger.warning("Error in TCP execute for sid=%r, op_id=%r: %s", sid, op_id, e)
		if transfer_use:
			raise ConnectionError(str(e)) from e