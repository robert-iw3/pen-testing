# backend/websocket_gunnershell.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import jwt, io, re
from contextlib import redirect_stdout, redirect_stderr, contextmanager

from . import config
from core.session_handlers import session_manager
from core.gunnershell.gunnershell import Gunnershell
from core import utils as core_utils

_CLEAR_ESC = re.compile(rb"\x1b\[[0-9;]*[HJ]|\x1bc")  # CSI ... H/J or RIS

router = APIRouter()

@contextmanager
def _capture_all(buf: io.StringIO):
    """Capture stdout/stderr AND anything routed via core.utils.echo."""
    original_echo = core_utils.echo

    def _echo_sink(msg, to_console=True, to_op=None, world_wide=False, color=None):
        try:
            s = msg if isinstance(msg, str) else msg.decode("utf-8", "ignore")
        except Exception:
            s = str(msg)
        buf.write(s)
        if not s.endswith("\n"):
            buf.write("\n")

    try:
        core_utils.echo = _echo_sink
        with redirect_stdout(buf), redirect_stderr(buf):
            yield
    finally:
        core_utils.echo = original_echo

@router.websocket("/ws/gunnershell/{sid}")
async def gunnershell_ws(ws: WebSocket, sid: str):
    await ws.accept()
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=1008); return
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        # op_id is not strictly needed here, we capture locally.
        _ = payload.get("sub")
    except jwt.InvalidTokenError:
        await ws.close(code=1008); return

    if sid not in session_manager.sessions:
        await ws.send_text("Session not found."); await ws.close(); return

    try:
        gs = Gunnershell(sid, None)  # console flavor; we capture output locally
        await ws.send_text("[*] GunnerShell connected. Type 'help' (exit to quit).")
    except Exception as e:
        await ws.send_text(f"[ERROR] {e}"); await ws.close(); return

    try:
        while True:
            line = (await ws.receive_text()).strip()
            if not line:
                continue

            want_clear = line.lower() in ("banner", "clear", "cls")

            buf = io.StringIO()
            with _capture_all(buf):
                ret = gs.interact(line, to_console=True, op_id=None)

            #text = buf.getvalue()
            raw = buf.getvalue().encode("utf-8", "ignore")

            if want_clear or _CLEAR_ESC.search(raw):
                await ws.send_text("\x00CLEAR\x00")
                raw = _CLEAR_ESC.sub(b"", raw)

            text = raw.decode("utf-8", "ignore")
            
            if text:
                await ws.send_text(text)

            if ret:
                if ret == "exit":
                    await ws.send_text("[*] Exiting GunnerShell."); await ws.close(); return
                if isinstance(ret, str) and ret.startswith("SIDSWITCH"):
                    try:
                        _, new_sid = ret.split(maxsplit=1)
                        gs = Gunnershell(new_sid, None)
                        await ws.send_text(f"[*] Switched to {new_sid}.")
                    except Exception as e:
                        await ws.send_text(f"[ERROR] SIDSWITCH failed: {e}")
                else:
                    await ws.send_text(str(ret))
    except WebSocketDisconnect:
        return
    except Exception as e:
        try:
            await ws.send_text(f"[ERROR] {e}")
        finally:
            await ws.close()
