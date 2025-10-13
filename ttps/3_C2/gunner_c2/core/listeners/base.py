import threading
from abc import ABC, abstractmethod
from typing import Dict, Optional
import uuid
import pkgutil
import importlib
import logging

log = logging.getLogger(__name__)

_reg_lock = threading.RLock()

class Listener(ABC):
	"""
	Abstract base: subclass and implement run_loop().
	The framework takes care of starting, stopping, exception handling.
	"""
	def __init__(self, ip: str, port: int, transport: str, to_console: bool=True, op_id: str=None, listener_id: str=None, profiles: Optional[str] = None):
		self.ip = ip
		self.port = port
		self.name = ""
		self.transport = transport
		self.to_console = to_console
		self.op_id = op_id
		self.id = listener_id       # your random ID
		self.sessions = []          # you can append session IDs here
		self.profiles = {}      # path to .cna, if any
		self._stop_event = threading.Event()
		self._thread: threading.Thread | None = None

	@abstractmethod
	def start(self, ip, port):
		"""Start the listener in its own daemon thread."""

	@abstractmethod
	def stop(self, timeout: float = None):
		"""Signal the loop to exit and wait for the thread."""

	@abstractmethod
	def is_alive(self) -> bool:
		"""Check if session is still alive"""

	@abstractmethod
	def run_loop(self, stop_event: threading.Event):
		""""Core Listener Logic"""

# registry of name → Listener subclass
LISTENER_CLASSES: dict[str, type[Listener]] = {}

# global registry so you can lookup by ID from anywhere
listeners: Dict[str, Listener] = {}
socket_to_listener: Dict[int, str] = {}

def create_listener(ip: str, port: int, transport: str, to_console: bool=True, op_id: str=None, profiles: Optional[dict] = None, certfile: str = None,
	keyfile: str = None) -> Listener:
	"""
	Instantiate, start, and register a new Listener subclass
	for the given transport name. Returns the running instance.
	"""
	cls = LISTENER_CLASSES.get(transport)
	if not cls:
		raise ValueError(f"No listener registered for transport {transport!r}")

	# Assign a random 8-char ID
	lid = uuid.uuid4().hex[:8]

	# Instantiate the concrete listener
	inst = cls(ip=ip, port=port, transport=transport, to_console=to_console, op_id=op_id, listener_id=lid, profiles=profiles)
	# Store & spin up its thread
	with _reg_lock:
		listeners[lid] = inst

	if transport in ("https"):
		inst.start(ip, port, certfile=certfile, keyfile=keyfile)

	else:
		inst.start(ip, port)
	return inst


def stop_listener(transport: str, port: int) -> Optional[str]:
	"""
	Stop & remove the listener matching transport+port. Returns its ID or None.
	"""
	for lid, inst in list(listeners.items()):
		if inst.transport == transport and inst.port == port:
			try:
				inst.stop()
			except Exception:
				log.exception("Error stopping listener %s", lid)
			# remove from registry
			del listeners[lid]
			return lid
	return None

def register_listener(*names: str):
	"""Register Listeners"""
	def deco(cls):
		for name in names:
			LISTENER_CLASSES[name] = cls
		return cls
	return deco

def load_listeners():
	"""
	Walk core/listeners/, import every .py (except this base),
	so @register_listener can populate LISTENER_CLASSES.
	"""

	pkg = importlib.import_module(__package__)  # core.listeners
	for finder, module_name, is_pkg in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
		if module_name.endswith(".base"):
			continue
		try:
			importlib.import_module(module_name)
		except Exception:
			log.exception("Failed to import listener module %r", module_name)
