# backend/websocket_sessions.py
import asyncio, json, hashlib
from typing import Any, Dict, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import jwt, re

from contextlib import suppress

from . import config
from core.session_handlers import session_manager
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

router = APIRouter()

# CSI/ANSI escape codes + stray control chars
_ANSI_RE  = re.compile(r'(?:\x1B[@-Z\\-_]|\x1B\[[0-?]*[ -/]*[@-~]|\x9B[0-?]*[ -/]*[@-~])')
_CTRL_RE  = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

# ---------- helpers ----------------------------------------------------------

def _sess_to_summary(sess) -> Dict[str, Any]:
	meta = getattr(sess, "metadata", {}) or {}
	return {
		"id":          str(getattr(sess, "sid", "")),
		"hostname":    _clean_text(meta.get("hostname", "")),
		"user":        _clean_text(meta.get("user", "")),
		"os":          _clean_text(meta.get("os", "")).lower(),
		"arch":        _clean_text(meta.get("arch", "")),
		"transport":   str(getattr(sess, "transport", "")).lower(),
		"integrity":   _clean_text(meta.get("integrity", "")),
		"last_checkin": getattr(sess, "last_seen", None) or getattr(sess, "created_at", None),
	}

def _serialize_sessions():
	return [_sess_to_summary(s) for s in list(session_manager.sessions.values())]

def _resolve_sid(sid: str) -> Optional[str]:
	try:
		if hasattr(session_manager, "resolve_sid"):
			return session_manager.resolve_sid(sid) or sid
	except Exception:
		pass
	return sid

async def _ws_send(ws: WebSocket, payload: Dict[str, Any]):
	# Safe send (ignore if client already closed)
	try:
		await ws.send_text(json.dumps(payload, separators=(",", ":"), default=str))
	except WebSocketDisconnect:
		raise
	except Exception:
		# swallow – writer task will exit on next iteration
		pass

def _clean_text(val):
	if not isinstance(val, str):
		return val
	s = _ANSI_RE.sub('', val)
	s = _CTRL_RE.sub('', s)
	return s.strip()

# ---------- command handlers -------------------------------------------------

async def _cmd_get(ws: WebSocket, req: Dict[str, Any]):
	sid = _resolve_sid(req.get("sid", ""))
	sess = session_manager.sessions.get(sid)
	if not sess:
		return await _ws_send(ws, {"type": "error", "req_id": req.get("req_id"), "error": "Session not found"})
	await _ws_send(ws, {"type": "session", "req_id": req.get("req_id"), "session": _sess_to_summary(sess)})

async def _cmd_kill(ws: WebSocket, req: Dict[str, Any]):
	sid = _resolve_sid(req.get("sid", ""))
	sess = session_manager.sessions.get(sid)
	if not sess:
		return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"Session not found"})

	transport = str(getattr(sess, "transport", "")).lower()
	meta = getattr(sess, "metadata", {}) or {}
	os_type = str(meta.get("os", "")).lower()

	if transport in ("http", "https"):
		ok = False
		try:
			if hasattr(session_manager, "kill_http_session"):
				ok = bool(session_manager.kill_http_session(sid, os_type))
		except Exception:
			ok = False
		if not ok:
			return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"No such HTTP session"})
		return await _ws_send(ws, {"type":"killed","req_id":req.get("req_id"),"id":sid,"transport":transport})

	# TCP
	try:
		is_tcp = False
		if hasattr(session_manager, "is_tcp_session"):
			is_tcp = bool(session_manager.is_tcp_session(sid))
		else:
			is_tcp = (transport == "tcp")

		if is_tcp:
			handler = getattr(sess, "handler", None)
			try:
				if handler and hasattr(handler, "close"):
					handler.close()
			finally:
				try:
					del session_manager.sessions[sid]
				except Exception:
					pass
			return await _ws_send(ws, {"type":"killed","req_id":req.get("req_id"),"id":sid,"transport":"tcp"})
	except Exception as e:
		return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":f"Failed to close TCP session: {e}"})

	await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"Unknown session type"})

async def _cmd_exec(ws: WebSocket, req: Dict[str, Any]):
	sid = _resolve_sid(req.get("sid", ""))
	cmd = req.get("cmd") or ""
	op_id = req.get("op_id") or "console"

	sess = session_manager.sessions.get(sid)
	if not sess:
		return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"Session not found"})

	transport = str(getattr(sess, "transport", "")).lower()

	loop = asyncio.get_running_loop()
	try:
		if transport in ("http", "https"):
			def _do_http():
				return http_exec.run_command_http(sid, cmd, op_id=op_id, timeout=30.0) or ""
			out = await loop.run_in_executor(None, _do_http)
		else:
			def _do_tcp():
				return tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, portscan_active=True,op_id=op_id) or ""
			out = await loop.run_in_executor(None, _do_tcp)

		await _ws_send(ws, {
			"type": "exec_result",
			"req_id": req.get("req_id"),
			"sid": sid,
			"output": out,
		})
	except Exception as e:
		await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":str(e)})

# ---------- the websocket route ---------------------------------------------

@router.websocket("/ws/sessions")
async def sessions_ws(ws: WebSocket):
	await ws.accept()

	# auth
	token = ws.query_params.get("token")
	if not token:
		await ws.close(code=1008); return
	try:
		jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
	except jwt.InvalidTokenError:
		await ws.close(code=1008); return

	# writer: push snapshots when changed
	last_hash = None
	async def writer():
		nonlocal last_hash
		try:
			while True:
				snap = {"type": "snapshot", "sessions": _serialize_sessions()}
				blob = json.dumps(snap, sort_keys=True, separators=(",", ":"), default=str).encode()
				h = hashlib.sha1(blob).hexdigest()
				if h != last_hash:
					await _ws_send(ws, snap)
					last_hash = h
				await asyncio.sleep(0.75)
		except (WebSocketDisconnect, asyncio.CancelledError):
			# Normal shutdown path: reader completed or task was cancelled.
			pass

	# reader: handle commands
	async def reader():
		actions = {
			"list":   lambda w, r: _ws_send(w, {"type":"snapshot","req_id":r.get("req_id"),"sessions":_serialize_sessions()}),
			"get":    _cmd_get,
			"kill":   _cmd_kill,
			"exec":   _cmd_exec,
			"ping":   lambda w, r: _ws_send(w, {"type":"pong","req_id":r.get("req_id")}),
		}
		while True:
			raw = await ws.receive_text()
			try:
				req = json.loads(raw)
			except Exception:
				await _ws_send(ws, {"type":"error","error":"Invalid JSON"}); continue
			act = (req.get("action") or "").lower()
			fn = actions.get(act)
			if not fn:
				await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":f"Unknown action '{act}'"}); continue
			await fn(ws, req)

	# run both concurrently
	writer_task = asyncio.create_task(writer())
	try:
		await reader()
	except WebSocketDisconnect:
		pass
	finally:
		writer_task.cancel()
		# Swallow the cancellation so Uvicorn doesn't log it as an error.
		with suppress(asyncio.CancelledError):
			await writer_task
