# gui/listeners_ws_client.py
from __future__ import annotations

import json
from typing import Optional

from PyQt5.QtCore import QObject, pyqtSignal, QUrl, QTimer
from PyQt5.QtWebSockets import QWebSocket


class ListenersWSClient(QObject):
	# connection lifecycle
	connected = pyqtSignal()
	disconnected = pyqtSignal()
	error = pyqtSignal(str)

	# server events
	snapshot = pyqtSignal(list)      # rows: list[dict]
	added = pyqtSignal(dict)         # row
	removed = pyqtSignal(str)        # id
	updated = pyqtSignal(dict)       # row

	# acks for create/stop
	created = pyqtSignal(dict)       # {"ok": bool, "row"?: dict, "error"?: str, "req_id"?: int}
	stopped = pyqtSignal(dict)       # {"ok": bool, "id"?: str, "error"?: str, "req_id"?: int}

	def __init__(self, base_url: str, token: str, parent: Optional[QObject] = None):
		super().__init__(parent)
		self.base_url = (base_url or "").rstrip("/")
		self.token = token
		self.ws = QWebSocket()
		self._req_seq = 0

		# ---- wire signals
		self.ws.connected.connect(self.connected)
		self.ws.disconnected.connect(self.disconnected)
		self.ws.textMessageReceived.connect(self._on_text)

		# PyQt5 uses .error, PyQt6 uses .errorOccurred — support both
		try:
			self.ws.error.connect(lambda *args: self.error.emit(self.ws.errorString()))  # type: ignore[attr-defined]
		except Exception:
			try:
				self.ws.errorOccurred.connect(lambda *_: self.error.emit(self.ws.errorString()))  # type: ignore[attr-defined]
			except Exception:
				pass

		# optional heartbeat (keeps some proxies happy)
		self._pong_timer = QTimer(self)
		self._pong_timer.setInterval(25_000)
		self._pong_timer.timeout.connect(self.ping)

	# ---------- connection ----------
	def open(self):
		"""Open the websocket to /ws/listeners with the JWT token query param."""
		if self.base_url.startswith("https://"):
			ws_base = "wss://" + self.base_url[len("https://") :]
		elif self.base_url.startswith("http://"):
			ws_base = "ws://" + self.base_url[len("http://") :]
		else:
			ws_base = self.base_url

		url = QUrl(f"{ws_base}/ws/listeners?token={self.token}")
		self.ws.open(url)
		self._pong_timer.start()

	def close(self):
		self._pong_timer.stop()
		self.ws.close()

	# ---------- helpers ----------
	def _next_req_id(self) -> int:
		self._req_seq += 1
		return self._req_seq

	def _send(self, obj: dict):
		try:
			self.ws.sendTextMessage(json.dumps(obj, separators=(",", ":"), default=str))
		except Exception as e:
			self.error.emit(str(e))

	# ---------- API ----------
	def request_list(self):
		"""Ask the server for a fresh snapshot."""
		self._send({"action": "listeners.list", "req_id": self._next_req_id()})

	def create(self, cfg: dict):
		"""
		Create a listener. Pass the dialog payload as-is; the server accepts
		both {type, bind_ip, port, name, profile, ...} and the v2 shape.
		"""
		msg = {"action": "listeners.create", "req_id": self._next_req_id()}
		if isinstance(cfg, dict):
			msg.update(cfg)
		self._send(msg)

	def stop(self, listener_id: str):
		"""Stop a listener by id."""
		self._send({"action": "listeners.stop", "id": str(listener_id or ""), "req_id": self._next_req_id()})

	def ping(self):
		"""Lightweight ping; server replies with 'pong' (ignored)."""
		self._send({"action": "ping", "req_id": self._next_req_id()})

	# ---------- inbound dispatch ----------
	def _on_text(self, txt: str):
		try:
			m = json.loads(txt)
		except Exception:
			self.error.emit("Invalid message from server")
			return

		t = m.get("type")
		if t == "listeners.snapshot":
			self.snapshot.emit(m.get("rows") or [])
		elif t == "listeners.added":
			self.added.emit(m.get("row") or {})
		elif t == "listeners.removed":
			self.removed.emit(str(m.get("id") or ""))
		elif t == "listeners.updated":
			self.updated.emit(m.get("row") or {})
		elif t == "listeners.created":
			self.created.emit(m)
		elif t == "listeners.stopped":
			self.stopped.emit(m)
		elif t == "pong":
			# no-op; heartbeat
			pass
		elif t == "error":
			self.error.emit(str(m.get("error") or "error"))
		# else: silently ignore unknown types (forward compatibility)
