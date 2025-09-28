# backend/websocket_listeners.py
from __future__ import annotations

import json
import asyncio
import contextlib
from typing import Any, Dict, Set, Tuple, List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import jwt

from . import config
from .logutil import get_logger, bind, redacts
from .listeners import _serialize_listener, ALLOWED_TYPES, _stop_instance_async
from core.listeners.base import listeners as CORE_REG, _reg_lock

router = APIRouter()
logger = get_logger("backend.websocket_listeners", file_basename="listeners_ws")

# Active websocket clients
_CLIENTS: Set[WebSocket] = set()

# ---------- helpers ----------

def _conflict_by_name(name: str) -> Tuple[bool, str]:
	"""
	Is there any listener with the same (case-insensitive) non-empty name?
	Returns (conflict, existing_id).
	"""
	if not name:
		return False, ""
	n = name.strip().lower()
	with _reg_lock:
		for lid, inst in CORE_REG.items():
			existing = str(getattr(inst, "name", "") or "").strip()
			if existing and existing.lower() == n:
				return True, lid
	return False, ""


def _conflict_by_port(port: int) -> Tuple[bool, str, str, str]:
	"""
	Is there any listener already using this port? (We treat the port as globally
	reserved across transports and IPs; adjust here if you want per-IP rules.)
	Returns (conflict, existing_id, transport, ip).
	"""
	p = int(port)
	with _reg_lock:
		for lid, inst in CORE_REG.items():
			try:
				if int(getattr(inst, "port", -1)) == p:
					return True, lid, str(getattr(inst, "transport", "")), str(getattr(inst, "ip", ""))
			except Exception:
				continue
	return False, "", "", ""


async def _ws_send(ws: WebSocket, payload: Dict[str, Any], log):
	try:
		txt = json.dumps(payload, separators=(",", ":"), default=str)
		await ws.send_text(txt)
		log.debug(
			"ws.send",
			extra={
				"payload_type": payload.get("type"),
				"req_id": payload.get("req_id"),
				"json_bytes": len(txt),
			},
		)
	except WebSocketDisconnect:
		raise
	except Exception as e:
		log.exception("ws.send.error", extra={"err": repr(e)})


async def _broadcast(payload: Dict[str, Any]):
	dead: list[WebSocket] = []
	txt = json.dumps(payload, separators=(",", ":"), default=str)
	for ws in list(_CLIENTS):
		try:
			await ws.send_text(txt)
		except Exception:
			dead.append(ws)
	for d in dead:
		with contextlib.suppress(Exception):
			_CLIENTS.discard(d)


def _snapshot_rows():
	with _reg_lock:
		return [_serialize_listener(inst) for inst in CORE_REG.values()]


def _install_change_hook():
	"""
	Allow the REST layer to notify us of add/remove/update so WS clients
	get live updates even when the REST API is used.
	"""
	from . import listeners as mod

	def _changed(kind: str, data: Dict[str, Any]):
		if kind == "added":
			payload = {"type": "listeners.added", "row": data}
		elif kind == "removed":
			payload = {"type": "listeners.removed", "id": data.get("id")}
		elif kind == "updated":
			payload = {"type": "listeners.updated", "row": data}
		else:
			return
		asyncio.get_event_loop().create_task(_broadcast(payload))

	mod.listeners_changed = _changed


_install_change_hook()

# ---------- WS endpoint ----------

@router.websocket("/ws/listeners")
async def listeners_ws(ws: WebSocket):
	await ws.accept()
	wsid = id(ws) & 0xFFFF_FFFF
	client = None
	try:
		client = f"{ws.client.host}:{ws.client.port}"  # type: ignore[attr-defined]
	except Exception:
		pass
	log = bind(logger, wsid=f"{wsid:x}", client=client)
	log.info("ws.connect", extra={"path": "/ws/listeners", "client": client})

	# ---- auth (match other websockets) ----
	token = ws.query_params.get("token")
	if not token:
		log.warning("ws.auth.missing_token")
		await ws.close(code=1008)
		return
	try:
		jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
		log.info("ws.auth.ok", extra={"token_preview": redacts(token, show=4)})
	except jwt.InvalidTokenError:
		log.warning("ws.auth.invalid")
		await ws.close(code=1008)
		return

	_CLIENTS.add(ws)

	# Initial snapshot so pre-created (CLI/REST) listeners appear immediately
	await _ws_send(ws, {"type": "listeners.snapshot", "rows": _snapshot_rows()}, log)

	try:
		while True:
			txt = await ws.receive_text()
			try:
				req = json.loads(txt)
			except Exception:
				await _ws_send(ws, {"type": "error", "error": "Invalid JSON"}, log)
				continue

			act = str(req.get("action") or "").lower()
			req_id = req.get("req_id")
			log.debug("ws.recv", extra={"action": act, "req_id": req_id})

			# ---------- Actions ----------
			if act in ("listeners.list", "list"):
				await _ws_send(
					ws,
					{"type": "listeners.snapshot", "req_id": req_id, "rows": _snapshot_rows()},
					log,
				)

			elif act in ("listeners.create", "create"):
				# Accept both v1 and v2 shapes
				t = (req.get("type") or req.get("transport") or "").lower().strip()
				if t not in ALLOWED_TYPES:
					await _ws_send(
						ws,
						{
							"type": "listeners.created",
							"req_id": req_id,
							"ok": False,
							"error": f"Unsupported listener type '{t}'",
						},
						log,
					)
					continue

				name = (req.get("name") or "").strip()
				if not name:
					await _ws_send(
						ws,
						{
							"type": "listeners.created",
							"req_id": req_id,
							"ok": False,
							"error": "Listener name must be provided!",
						},
						log,
					)
					continue

				host = req.get("bind_ip") or req.get("ip") or req.get("host") or "0.0.0.0"
				port = int(req.get("port") or req.get("bind_port") or 0)
				profiles = req.get("profile") or req.get("profiles") or req.get("base_path")

				# ---- hard conflicts: name OR port ----
				name_conflict, name_lid = _conflict_by_name(name)
				if name_conflict:
					await _ws_send(
						ws,
						{
							"type": "listeners.created",
							"req_id": req_id,
							"ok": False,
							"error": f"Listener name '{name}' is already in use (id={name_lid}).",
						},
						log,
					)
					continue

				port_conflict, port_lid, port_t, port_ip = _conflict_by_port(port)
				if port_conflict:
					await _ws_send(
						ws,
						{
							"type": "listeners.created",
							"req_id": req_id,
							"ok": False,
							"error": f"Port {port} is already used by {port_t or 'listener'} "
									 f"on {port_ip or '0.0.0.0'} (id={port_lid}).",
						},
						log,
					)
					continue

				from core.listeners.base import create_listener  # builder in core

				kwargs = {"profiles": profiles}
				if t in ("https", "tls"):
					if req.get("certfile"):
						kwargs["certfile"] = req["certfile"]
					if req.get("keyfile"):
						kwargs["keyfile"] = req["keyfile"]

				# Snapshot current IDs to roll back if create fails
				with _reg_lock:
					before_ids = set(CORE_REG.keys())

				try:
					inst = create_listener(host, port, t, **kwargs)
				except TypeError:
					inst = create_listener(host, port, t, profiles=profiles)
				except Exception as e:
					# Roll back any newly-registered ghost(s) added by core before failing
					with _reg_lock:
						new_ids = set(CORE_REG.keys()) - before_ids
						for lid in list(new_ids):
							CORE_REG.pop(lid, None)
					await _ws_send(
						ws,
						{
							"type": "listeners.created",
							"req_id": req_id,
							"ok": False,
							"error": f"Failed to start listener: {e}",
						},
						log,
					)
					continue

				# Assign friendly name
				try:
					inst.name = name or f"{t}:{port}"
				except Exception:
					pass

				row = _serialize_listener(inst)

				# Ack creator and broadcast to everyone
				await _ws_send(ws, {"type": "listeners.created", "req_id": req_id, "ok": True, "row": row}, log)
				await _broadcast({"type": "listeners.added", "row": row})

			elif act in ("listeners.stop", "stop"):
				lid = (req.get("id") or req.get("listener_id") or "").strip()
				if not lid:
					await _ws_send(
						ws,
						{"type": "listeners.stopped", "req_id": req_id, "ok": False, "error": "Missing id"},
						log,
					)
					continue

				with _reg_lock:
					inst = CORE_REG.get(lid)
				if not inst:
					await _ws_send(
						ws,
						{"type": "listeners.stopped", "req_id": req_id, "ok": False, "error": "Listener not found"},
						log,
					)
					continue

				# Stop in background; remove from registry immediately to update UI
				try:
					asyncio.get_event_loop().run_in_executor(None, _stop_instance_async, inst)
				except Exception:
					_stop_instance_async(inst)

				with _reg_lock:
					CORE_REG.pop(lid, None)

				await _ws_send(ws, {"type": "listeners.stopped", "req_id": req_id, "ok": True, "id": lid}, log)
				await _broadcast({"type": "listeners.removed", "id": lid})

			elif act in ("ping",):
				await _ws_send(ws, {"type": "pong", "req_id": req_id}, log)

			else:
				await _ws_send(ws, {"type": "error", "error": f"Unknown action '{act}'", "req_id": req_id}, log)

	except WebSocketDisconnect:
		log.info("ws.disconnect")
	finally:
		_CLIENTS.discard(ws)
		log.info("ws.cleanup")
