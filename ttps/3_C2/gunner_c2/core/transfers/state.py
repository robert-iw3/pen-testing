import logging
logger = logging.getLogger(__name__)

import json, os, threading, time, uuid
import errno, tempfile, shutil
from dataclasses import dataclass, asdict, field
from typing import Optional, Literal, Dict, Any, List

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

STATUS = Literal["init","running","paused","done","error","cancelled"]
DIR = os.path.expanduser("~/.gunnerc2/transfers")

def _ensure_dir(path: str) -> None:
	os.makedirs(path, exist_ok=True)

@dataclass
class TransferState:
	tid: str
	sid: str
	direction: Literal["download","upload"]  # download = agent -> server
	remote_path: str
	local_path: str
	is_folder: bool
	os_type: Literal["windows","linux"]
	transport: str
	chunk_size: int
	total_bytes: int
	bytes_done: int = 0
	next_index: int = 0
	total_chunks: int = 0
	created_at: float = field(default_factory=time.time)
	updated_at: float = field(default_factory=time.time)
	status: STATUS = "init"
	error: Optional[str] = None
	tmp_local_path: Optional[str] = None  # .part destination
	archive_remote_path: Optional[str] = None  # when folder is archived remotely
	cleanup_remote_cmd: Optional[str] = None  # to delete remote archive
	options: Dict[str, Any] = field(default_factory=dict)  # compress/encrypt knobs

	def to_dict(self) -> Dict[str, Any]:
		d = asdict(self)
		return d

	@classmethod
	def from_dict(cls, d: Dict[str, Any]) -> "TransferState":
		return cls(**d)


class StateStore:
	"""
	Thread-safe, crash-safe persistence for TransferState.
	Layout: ~/.gunnerc2/transfers/<sid>/<tid>/{state.json, data.part}
	"""
	def __init__(self, base_dir: str = DIR):
		self.base = base_dir
		_ensure_dir(self.base)
		self._lock = threading.RLock()
		# per-tid locks to reduce contention
		self._tid_locks: Dict[str, threading.RLock] = {}

	def _tid_dir(self, sid: str, tid: str) -> str:
		p = os.path.join(self.base, sid, tid)
		_ensure_dir(p)
		return p

	def _state_path(self, sid: str, tid: str) -> str:
		return os.path.join(self._tid_dir(sid, tid), "state.json")

	def _tmp_path(self, sid: str, tid: str) -> str:
		return os.path.join(self._tid_dir(sid, tid), "data.part")

	def lock_for(self, tid: str) -> threading.RLock:
		with self._lock:
			if tid not in self._tid_locks:
				self._tid_locks[tid] = threading.RLock()
			return self._tid_locks[tid]

	def save(self, st: TransferState) -> None:
		st.updated_at = time.time()
		path = self._state_path(st.sid, st.tid)
		tmp  = path + ".tmp"
		with self.lock_for(st.tid):
			with open(tmp, "w", encoding="utf-8") as f:
				json.dump(st.to_dict(), f, indent=2, sort_keys=True)
			os.replace(tmp, path)
			# Always keep tmp_local_path aligned to current sid/tid
			st.tmp_local_path = self._tmp_path(st.sid, st.tid)
			# Make sure its directory exists
			os.makedirs(os.path.dirname(st.tmp_local_path), exist_ok=True)

	def load(self, sid: str, tid: str) -> TransferState:
		path = self._state_path(sid, tid)
		with self.lock_for(tid):
			with open(path, "r", encoding="utf-8") as f:
				d = json.load(f)
				st = TransferState.from_dict(d)
				st.tmp_local_path = self._tmp_path(sid, tid)
				return st

	def exists(self, sid: str, tid: str) -> bool:
		return os.path.exists(self._state_path(sid, tid))

	def finalize(self, st: TransferState) -> None:
		# atomic finalize: .part -> final; handle cross-device safely
		with self.lock_for(st.tid):
			if not (st.tmp_local_path and os.path.exists(st.tmp_local_path)):
				return
			final_dir = os.path.dirname(st.local_path)
			_ensure_dir(final_dir)
			try:
				os.replace(st.tmp_local_path, st.local_path)
			except OSError as e:
				# Cross-device link (EXDEV): copy into a temp file in final_dir, then atomic replace
				if getattr(e, "errno", None) == errno.EXDEV:
					with open(st.tmp_local_path, "rb") as src, tempfile.NamedTemporaryFile(dir=final_dir, delete=False) as dst:
						shutil.copyfileobj(src, dst, 1024 * 1024)
						dst.flush()
						os.fsync(dst.fileno())
						temp_in_final = dst.name
					# Atomic within the target FS
					os.replace(temp_in_final, st.local_path)
					# Remove original .part after successful replace
					try:
						os.remove(st.tmp_local_path)
					except Exception:
						pass
				else:
					raise