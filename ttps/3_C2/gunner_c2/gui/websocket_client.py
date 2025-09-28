# gui/websocket_client.py
from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Dict, Optional

from PyQt5.QtCore import QObject, QTimer, pyqtSignal, QUrl
from PyQt5.QtNetwork import QAbstractSocket
from PyQt5.QtWebSockets import QWebSocket


def _make_ws_url(base_http_url: str, path: str, token: str) -> QUrl:
    """
    Build ws(s):// URL from http(s):// base.
    """
    if base_http_url.startswith("https://"):
        ws_base = "wss://" + base_http_url[len("https://") :]
    elif base_http_url.startswith("http://"):
        ws_base = "ws://" + base_http_url[len("http://") :]
    else:
        # Best effort
        ws_base = base_http_url
    if not path.startswith("/"):
        path = "/" + path
    return QUrl(f"{ws_base}{path}?token={token}")


class SessionsWSClient(QObject):
    """
    High-level WebSocket wrapper for /ws/sessions.
    Emits snapshots in real time and exposes request/response helpers
    for get/kill/exec.
    """
    # connection state
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    error = pyqtSignal(str)

    # high-level messages
    snapshot = pyqtSignal(list)              # list[SessionSummary]
    session = pyqtSignal(dict)               # single session (reply to "get")
    killed = pyqtSignal(str, str)            # (sid, transport)
    execResult = pyqtSignal(str, str, str)   # (req_id, sid, output)
    rawMessage = pyqtSignal(dict)            # all parsed frames

    def __init__(self, api, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.api = api
        self.ws = QWebSocket()
        self._cache: Dict[str, dict] = {}        # sid -> session summary
        self._req_handlers: Dict[str, Callable[[dict], None]] = {}

        # reconnect/backoff
        self._reconnect_ms = 1000
        self._reconnect_timer = QTimer(self)
        self._reconnect_timer.setSingleShot(True)
        self._reconnect_timer.timeout.connect(self._open)

        # keepalive
        self._ping_timer = QTimer(self)
        self._ping_timer.setInterval(20000)
        self._ping_timer.timeout.connect(self._send_ping)

        # wire WS
        self.ws.connected.connect(self._on_connected)
        self.ws.disconnected.connect(self._on_disconnected)
        if hasattr(self.ws, "errorOccurred"):
            self.ws.errorOccurred.connect(self._on_error)  # Qt >= 5.15
        else:
            self.ws.error.connect(self._on_error)
        self.ws.textMessageReceived.connect(self._on_message)

    # ---- public -------------------------------------------------------------

    def open(self):
        self._reconnect_ms = 1000
        self._open()

    def close(self):
        self._ping_timer.stop()
        self._reconnect_timer.stop()
        try:
            self.ws.close()
        except Exception:
            pass

    # ---- cache --------------------------------------------------------------
    def get_cached(self, sid: str) -> Optional[dict]:
        return self._cache.get(sid)

    # requests (optionally with per-request callback)
    def list_now(self, cb: Optional[Callable[[dict], None]] = None) -> str:
        return self._send({"action": "list"}, cb)

    def get(self, sid: str, cb: Optional[Callable[[dict], None]] = None) -> str:
        return self._send({"action": "get", "sid": sid}, cb)

    def kill(self, sid: str, cb: Optional[Callable[[dict], None]] = None) -> str:
        return self._send({"action": "kill", "sid": sid}, cb)

    def exec(self, sid: str, cmd: str, op_id: str = "console",
             cb: Optional[Callable[[dict], None]] = None) -> str:
        return self._send({"action": "exec", "sid": sid, "cmd": cmd, "op_id": op_id}, cb)

    # convenience for other widgets
    def get_cached(self, sid: str) -> Optional[dict]:
        return self._cache.get(sid)

    def all_cached(self) -> list:
        return list(self._cache.values())

    def request_snapshot(self, cb: Optional[Callable[[dict], None]] = None) -> str:
        # alias for list_now(); used by graph or tabs to nudge a refresh
        return self.list_now(cb)

    # ---- internals ----------------------------------------------------------

    def _open(self):
        url = _make_ws_url(self.api.base_url, "/ws/sessions", self.api.token)
        self.ws.open(url)

    def _schedule_reconnect(self):
        # exponential-ish backoff up to ~10s
        self._reconnect_ms = min(int(self._reconnect_ms * 1.7), 10000)
        self._reconnect_timer.start(self._reconnect_ms)

    def _send(self, payload: Dict[str, Any],
              cb: Optional[Callable[[dict], None]] = None) -> str:
        req_id = str(uuid.uuid4())
        payload = dict(payload)
        payload["req_id"] = req_id
        try:
            self.ws.sendTextMessage(json.dumps(payload, separators=(",", ":")))
        except Exception as e:
            # if we failed to send, bubble an error and try to reconnect
            self.error.emit(f"send failed: {e}")
            self._schedule_reconnect()
        if cb:
            self._req_handlers[req_id] = cb
        return req_id

    def _send_ping(self):
        try:
            self.ws.sendTextMessage(json.dumps({"action": "ping"}, separators=(",", ":")))
        except Exception:
            self._schedule_reconnect()

    # ---- slots --------------------------------------------------------------

    def _on_connected(self):
        self.connected.emit()
        self._ping_timer.start()
        # immediately request a fresh list too (writer pushes snapshots anyway)
        self.list_now()

    def _on_disconnected(self):
        self.disconnected.emit()
        self._ping_timer.stop()
        self._schedule_reconnect()

    def _on_error(self, err):
        # err is enum int in Qt5; show readable text if possible
        try:
            name = QAbstractSocket.SocketError(err).name if isinstance(err, int) else str(err)
        except Exception:
            name = self.ws.errorString()
        self.error.emit(name)

    def _on_message(self, txt: str):
        try:
            msg = json.loads(txt)
        except Exception:
            self.rawMessage.emit({"type": "parse_error", "raw": txt})
            return

        self.rawMessage.emit(msg)

        t = (msg.get("type") or "").lower()
        rid = msg.get("req_id")

        # dispatch per-type signals
        if t == "snapshot":
            sessions = msg.get("sessions") or []
            # refresh local cache
            new_cache: Dict[str, dict] = {}
            for s in sessions:
                try:
                    sid = str(s.get("id") or s.get("sid") or "")
                    if sid:
                        new_cache[sid] = s
                except Exception:
                    pass
            self._cache = new_cache
            self.snapshot.emit(sessions)
        elif t == "session":
            s = msg.get("session") or {}
            try:
                sid = str(s.get("id") or s.get("sid") or "")
                if sid:
                    self._cache[sid] = s
            except Exception:
                pass
            self.session.emit(s)

        elif t == "killed":
            sid = str(msg.get("id", ""))
            if sid: self._cache.pop(sid, None)
            self.killed.emit(sid, str(msg.get("transport", "")))
        elif t == "exec_result":
            self.execResult.emit(str(rid or ""), str(msg.get("sid", "")), msg.get("output") or "")
        elif t == "error":
            self.error.emit(str(msg.get("error", "unknown error")))
        # handle any pending per-request callback
        cb = self._req_handlers.pop(rid, None) if rid else None
        if cb:
            try:
                cb(msg)
            except Exception:
                pass

class OperatorsWSClient(QObject):
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    error = pyqtSignal(str)

    snapshot = pyqtSignal(list)     # list[Operator]
    added = pyqtSignal(dict)
    updated = pyqtSignal(dict)
    deleted = pyqtSignal(str)
    rawMessage = pyqtSignal(dict)

    loggedIn = pyqtSignal(dict)   # {"token": ..., "me": {...}}

    def __init__(self, api, parent=None):
        super().__init__(parent)
        self.api = api
        self.ws = QWebSocket()
        self._req_handlers = {}
        self._reconnect_ms = 1000

        self.ws.connected.connect(self._on_connected)
        self.ws.disconnected.connect(self._on_disconnected)
        if hasattr(self.ws, "errorOccurred"):
            self.ws.errorOccurred.connect(self._on_error)
        else:
            self.ws.error.connect(self._on_error)
        self.ws.textMessageReceived.connect(self._on_message)

        self._reconnect_timer = QTimer(self); self._reconnect_timer.setSingleShot(True)
        self._reconnect_timer.timeout.connect(self._open)

        self._ping_timer = QTimer(self); self._ping_timer.setInterval(20000)
        self._ping_timer.timeout.connect(self._send_ping)

    def login(self, username: str, password: str, cb=None):
        return self._send({"action":"login","username":username,"password":password}, cb)

    def open(self): self._reconnect_ms = 1000; self._open()
    def close(self):
        self._ping_timer.stop(); self._reconnect_timer.stop()
        try: self.ws.close()
        except Exception: pass

    # actions
    def list_now(self, cb=None): return self._send({"action":"list"}, cb)
    def add(self, username, password, role, cb=None):
        return self._send({"action":"add","username":username,"password":password,"role":role}, cb)
    def update(self, ident, username_new=None, password_new=None, role_new=None, cb=None):
        payload = {"action":"update","id":ident}
        if username_new is not None: payload["username_new"]=username_new
        if password_new is not None: payload["password_new"]=password_new
        if role_new is not None: payload["role_new"]=role_new
        return self._send(payload, cb)
    def delete(self, ident, cb=None):
        return self._send({"action":"delete","id":ident}, cb)

    # internals
    def _open(self):
        url = _make_ws_url(self.api.base_url, "/ws/operators", self.api.token)
        self.ws.open(url)
    def _schedule_reconnect(self):
        self._reconnect_ms = min(int(self._reconnect_ms*1.7), 10000)
        self._reconnect_timer.start(self._reconnect_ms)
    def _send(self, payload, cb=None):
        rid = str(uuid.uuid4())
        payload = dict(payload); payload["req_id"] = rid
        try:
            self.ws.sendTextMessage(json.dumps(payload, separators=(",",":")))
        except Exception as e:
            self.error.emit(f"send failed: {e}"); self._schedule_reconnect()
        if cb: self._req_handlers[rid] = cb
        return rid
    def _send_ping(self):
        try: self.ws.sendTextMessage(json.dumps({"action":"ping"}))
        except Exception: self._schedule_reconnect()

    # slots
    def _on_connected(self):
        self.connected.emit(); self._ping_timer.start(); self.list_now()
    def _on_disconnected(self):
        self.disconnected.emit(); self._ping_timer.stop(); self._schedule_reconnect()
    def _on_error(self, err):
        try: name = QAbstractSocket.SocketError(err).name if isinstance(err,int) else str(err)
        except Exception: name = self.ws.errorString()
        self.error.emit(name)
    def _on_message(self, txt):
        try: msg = json.loads(txt)
        except Exception: self.rawMessage.emit({"type":"parse_error","raw":txt}); return
        self.rawMessage.emit(msg)

        t = (msg.get("type") or "").lower(); rid = msg.get("req_id")
        if t == "snapshot":
            self.snapshot.emit(msg.get("operators") or [])

        elif t == "added":
            self.added.emit(msg.get("operator") or {})

        elif t == "updated":
            self.updated.emit(msg)

        elif t == "deleted":
            self.deleted.emit(str(msg.get("id","")))

        elif t == "error":
            self.error.emit(str(msg.get("error","unknown error")))

        elif t == "login_ok":
            token = msg.get("token")
            me = msg.get("me") or {}
            # stash the token so other WS (e.g., sessions) can be opened with it
            try:
                # if your APIClient is shared, update it here:
                self.api.token = token
                self.api.headers = {"Authorization": f"Bearer {token}"}
            except Exception:
                pass
            self.loggedIn.emit({"token": token, "me": me})
        cb = self._req_handlers.pop(rid, None) if rid else None
        if cb:
            try: cb(msg)
            except Exception: pass
