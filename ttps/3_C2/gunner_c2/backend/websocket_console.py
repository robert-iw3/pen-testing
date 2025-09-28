# backend/websocket_console.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import jwt  # PyJWT

from . import config
from core.session_handlers import session_manager
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

router = APIRouter()

@router.websocket("/ws/sessions/{sid}")
async def session_ws(ws: WebSocket, sid: str):
    await ws.accept()
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=1008); return
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        op_id = payload.get("sub") or "console"
    except jwt.InvalidTokenError:
        await ws.close(code=1008); return

    sess = session_manager.sessions.get(sid)
    if not sess:
        await ws.send_text("Session not found."); await ws.close(); return

    meta = getattr(sess, "metadata", {}) or {}
    await ws.send_text(f"** Connected to {meta.get('hostname','?')} as {meta.get('user','?')} ({meta.get('os','?')}/{meta.get('arch','?')}) **")

    try:
        while True:
            cmd = (await ws.receive_text()).strip()
            if not cmd:
                continue
            tr = str(getattr(sess, "transport", "")).lower()
            if tr in ("http", "https"):
                out = http_exec.run_command_http(sid, cmd, op_id=op_id, timeout=60.0)
            else:
                out = tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, op_id=op_id)
            await ws.send_text(out or "")
    except WebSocketDisconnect:
        return
    except Exception as e:
        try:
            await ws.send_text(f"[ERROR] {e}")
        finally:
            await ws.close()
