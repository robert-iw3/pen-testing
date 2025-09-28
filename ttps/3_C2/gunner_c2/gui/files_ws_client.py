# gui/files_ws_client.py
from PyQt5.QtCore import QObject, pyqtSignal, QUrl
from PyQt5.QtWebSockets import QWebSocket
from PyQt5.QtNetwork import QAbstractSocket
import json, os, zipfile, tarfile, tempfile, shutil

class FilesWSClient(QObject):
	connected = pyqtSignal()
	error = pyqtSignal(str)
	listed = pyqtSignal(str, object, bool)  # path, entries, ok
	dl_begin = pyqtSignal(str, str)         # tid, name
	dl_chunk = pyqtSignal(bytes)            # raw file bytes
	dl_meta = pyqtSignal(str, int)  		# tid, total_bytes
	dl_end = pyqtSignal(str, str, str)      # tid, status, error
	up_progress = pyqtSignal(int, int)      # written, total
	up_result = pyqtSignal(str, str)        # status, error
	drives = pyqtSignal(object)             # list[dict]  -> "This PC"
	quickpaths = pyqtSignal(object)         # dict        -> Quick Access
	created = pyqtSignal(str, str, bool, str)  # kind, path, ok, error
	deleted = pyqtSignal(str, bool, str)  # path, ok, error

	def __init__(self, base_url: str, token: str, parent=None):
		super().__init__(parent)
		self.base_url = base_url.rstrip("/")
		self.token = token
		self.ws = QWebSocket()
		self._pending_text: list[str] = []
		self._ul_explicit_finish = False
		self._tmp_archive_for_upload: str | None = None

		# robust error hookup across PyQt5 versions
		if hasattr(self.ws, "errorOccurred"):
			self.ws.errorOccurred.connect(lambda _: self.error.emit("websocket error"))
		else:
			self.ws.error.connect(lambda *_: self.error.emit("websocket error"))

		# flush when connected
		if hasattr(self.ws, "connected"):
			self.ws.connected.connect(self._on_connected)

		self.ws.textMessageReceived.connect(self._on_text)
		self.ws.binaryMessageReceived.connect(lambda b: self.dl_chunk.emit(bytes(b)))

	def _on_connected(self):
		self.connected.emit()
		# flush queued messages
		while self._pending_text:
			self.ws.sendTextMessage(self._pending_text.pop(0))

	def open(self):
		ws_url = self.base_url.replace("http", "ws", 1) + f"/ws/files?token={self.token}"
		self.ws.open(QUrl(ws_url))

	def delete(self, sid: str, remote_path: str, *, folder: bool = False):
		"""
		Request backend to delete file/folder at remote_path.
		folder=True allows recursive folder delete (server enforces policies).
		"""
		msg = {"action": "fs.delete", "sid": sid, "path": remote_path, "folder": bool(folder), "req_id": "del"}
		self._send(msg)

	# -------- API --------
	def list_dir(self, sid: str, path: str):
		self._send({"action":"fs.list","sid":sid,"path":path,"req_id":"list"})

	def new_folder(self, sid: str, parent_or_full: str, name: str | None = None, *, req_id: int | None = None):
		msg = {"action":"fs.new_folder","sid":sid}
		if name is None:
			msg["path"] = parent_or_full
		else:
			msg["dir"] = parent_or_full; msg["name"] = name
		if req_id is not None: msg["req_id"] = req_id
		self._send(msg)  # <-- was _send_json

	def new_text(self, sid: str, parent_or_full: str, name: str | None = None, *, req_id: int | None = None):
		msg = {"action":"fs.new_text","sid":sid}
		if name is None:
			msg["path"] = parent_or_full
		else:
			msg["dir"] = parent_or_full; msg["name"] = name
		if req_id is not None: msg["req_id"] = req_id
		self._send(msg)  # <-- was _send_json

	def start_download(self, sid: str, remote_path: str, *, folder: bool = False):
		self._send({"action":"fs.download","sid":sid,"path":remote_path,"req_id":"dl","folder": bool(folder)})

	def start_upload(self, sid: str, local_path: str, remote_path: str):
		size = os.path.getsize(local_path)
		self._ul_explicit_finish = False
		self._send({"action":"fs.upload.begin","sid":sid,"remote_path":remote_path,"size":size,"req_id":"up"})
		# after accept, stream
		def _stream():
			with open(local_path, "rb") as f:
				chunk = f.read(256*1024)
				while chunk:
					self.ws.sendBinaryMessage(chunk)
					chunk = f.read(256*1024)
			# only send finish if server said it's required
			if self._ul_explicit_finish:
				self._send({"action":"fs.upload.finish"})
		self._pending_upload_stream = _stream  # run when accept arrives

	# --- folder upload with server-side extraction ---
	def start_upload_folder(self, sid: str, local_dir: str, remote_dir: str, *, os_type: str = ""):
		"""
		Pack `local_dir` into a temp archive (zip on Windows targets, tar.gz on posix),
		then upload it with `folder: True` so the server extracts into `remote_dir`.
		"""
		if not os.path.isdir(local_dir):
			self.error.emit(f"Folder not found: {local_dir}")
			return

		use_zip = (os_type or "").lower() == "windows"
		suffix = ".zip" if use_zip else ".tar.gz"

		fd, tmp_path = tempfile.mkstemp(prefix="gc2_ul_arch_", suffix=suffix)
		os.close(fd)
		base = os.path.basename(os.path.normpath(local_dir)) or "folder"

		try:
			if use_zip:
				with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
					for root, _, files in os.walk(local_dir):
						for name in files:
							full = os.path.join(root, name)
							arc = os.path.join(base, os.path.relpath(full, local_dir)).replace("\\", "/")
							zf.write(full, arcname=arc)
			else:
				with tarfile.open(tmp_path, "w:gz") as tf:
					tf.add(local_dir, arcname=base, recursive=True)
		except Exception as e:
			try: os.remove(tmp_path)
			except Exception: pass
			self.error.emit(f"Failed to archive folder: {e}")
			return

		self._tmp_archive_for_upload = tmp_path
		size = os.path.getsize(tmp_path)
		self._ul_explicit_finish = False
		# Note: send folder=True + remote_dir so the backend extracts into that directory
		self._send({"action":"fs.upload.begin","sid":sid,"remote_dir":remote_dir,"folder":True,"size":size,"req_id":"up"})

		def _stream():
			with open(tmp_path, "rb") as f:
				chunk = f.read(256*1024)
				while chunk:
					self.ws.sendBinaryMessage(chunk)
					chunk = f.read(256*1024)
			if self._ul_explicit_finish:
				self._send({"action":"fs.upload.finish"})
		self._pending_upload_stream = _stream

	# -------- explorer helpers --------
	def get_drives(self, sid: str):
		self._send({"action":"fs.drives","sid":sid,"req_id":"drives"})

	def get_quickpaths(self, sid: str):
		self._send({"action":"fs.quickpaths","sid":sid,"req_id":"qp"})

	# -------- internals --------
	def _send(self, obj: dict):
		s = json.dumps(obj, separators=(",", ":"))
		# queue if not connected yet
		if self.ws.state() != QAbstractSocket.ConnectedState:
			self._pending_text.append(s)
		else:
			self.ws.sendTextMessage(s)

	def _on_text(self, s: str):
		try:
			m = json.loads(s)
		except Exception:
			return
		t = (m.get("type") or "").lower()

		if t == "fs.list":
			path = m.get("path") or ""
			entries = m.get("entries") or []

			# --- normalize various backend shapes ---
			# some backends accidentally send a dict: {"path": "...", "entries": [...]}
			if isinstance(entries, dict):
				path = entries.get("path", path)
				entries = entries.get("entries", [])

			# final guard: must be a list for the signal
			if not isinstance(entries, list):
				entries = []

			self.listed.emit(path, entries, bool(m.get("ok", True)))
			return

		elif t == "deleted":
			self.deleted.emit(str(m.get("path", "")), bool(m.get("ok", False)), str(m.get("error", "")))
			return

		elif t == "fs.new.result":
			self.created.emit(
				str(m.get("kind") or ""),
				str(m.get("path") or ""),
				bool(m.get("ok")),
				str(m.get("error") or "")
			)

		elif t == "fs.download.meta":
			self.dl_meta.emit(m.get("tid",""), int(m.get("total_bytes") or 0))

		elif t == "fs.download.begin":
			self.dl_begin.emit(m.get("tid",""), m.get("name","file.bin"))

		elif t == "fs.download.end":
			self.dl_end.emit(m.get("tid",""), m.get("status",""), m.get("error") or "")

		elif t == "fs.upload.accept":
			self._ul_explicit_finish = bool(m.get("explicit_finish", False))
			cb = getattr(self, "_pending_upload_stream", None)
			if cb:
				self._pending_upload_stream = None
				cb()
				
		elif t == "fs.upload.progress":
			self.up_progress.emit(int(m.get("written") or 0), int(m.get("total") or 0))

		elif t == "fs.upload.result":
			self.up_result.emit(m.get("status",""), m.get("error") or "")

			# cleanup any temp archive from folder uploads
			try:
				if self._tmp_archive_for_upload and os.path.exists(self._tmp_archive_for_upload):
					try:
						os.remove(self._tmp_archive_for_upload)
					except Exception:
						pass
			finally:
				self._tmp_archive_for_upload = None

		elif t == "pong":
			pass

		elif t == "fs.drives":
			rows = m.get("drives") or []
			if not isinstance(rows, list): rows = []
			self.drives.emit(rows)

		elif t == "fs.quickpaths":
			self.quickpaths.emit(m.get("paths") or {})
			
		elif t == "error":
			self.error.emit(m.get("error") or "error")
