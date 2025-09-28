# backend/sessions.py
from fastapi import APIRouter, HTTPException
from .schemas import SessionSummary

from core.session_handlers import session_manager
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

router = APIRouter()

def _sess_to_summary(sess) -> SessionSummary:
    meta = getattr(sess, "metadata", {}) or {}
    return {
        "id": getattr(sess, "sid", ""),
        "hostname": meta.get("hostname", ""),
        "user": meta.get("user",""),
        "os": meta.get("os",""),
        "arch": meta.get("arch",""),
        "transport": getattr(sess, "transport",""),
        "integrity": meta.get("integrity",""),
        "last_checkin": getattr(sess, "last_seen", None) or getattr(sess, "created_at", None),
    }

def _initialized(sess) -> bool:
    meta = getattr(sess, "metadata", {}) or {}
    # Require minimal identity before surfacing to UI
    return bool(meta.get("user"))

@router.get("", response_model=list[SessionSummary])
def list_sessions():
    return [_sess_to_summary(s) for s in session_manager.sessions.values() if _initialized(s)]

@router.get("/{sid}", response_model=SessionSummary)
def get_session(sid: str):
    sess = session_manager.sessions.get(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    return _sess_to_summary(sess)

@router.post("/{sid}/exec")
def exec_once(sid: str, cmd: str, op_id: str = "console"):
    sess = session_manager.sessions.get(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    tr = str(getattr(sess, "transport", "")).lower()
    if tr in ("http","https"):
        out = http_exec.run_command_http(sid, cmd, op_id=op_id, timeout=30.0)
    else:
        out = tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, op_id=op_id)
    return {"output": (out or "")}

@router.post("/{sid}/kill")
def kill_session(sid: str):
    """
    Kill/close a session, matching the CLI semantics:
      - Resolve aliases/short ids via session_manager.resolve_sid if available
      - HTTP/HTTPS: use session_manager.kill_http_session(sid, os_type)
      - TCP: close handler socket and remove from session_manager.sessions
    """
    # Resolve aliases/short forms if supported
    resolved = None
    try:
        if hasattr(session_manager, "resolve_sid"):
            resolved = session_manager.resolve_sid(sid)
    except Exception:
        resolved = None
    resolved = resolved or sid

    sess = session_manager.sessions.get(resolved)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    transport = str(getattr(sess, "transport", "")).lower()
    meta = getattr(sess, "metadata", {}) or {}
    os_type = str(meta.get("os", "")).lower()

    # HTTP/HTTPS sessions
    if transport in ("http", "https"):
        ok = False
        try:
            if hasattr(session_manager, "kill_http_session"):
                ok = bool(session_manager.kill_http_session(resolved, os_type))
        except Exception:
            ok = False
        if not ok:
            # Mirror CLI: "No such HTTP session"
            raise HTTPException(status_code=404, detail="No such HTTP session")
        return {"status": "killed", "id": resolved, "transport": transport}

    # TCP sessions
    try:
        is_tcp = False
        if hasattr(session_manager, "is_tcp_session"):
            is_tcp = bool(session_manager.is_tcp_session(resolved))
        else:
            is_tcp = (transport == "tcp")

        if is_tcp:
            handler = getattr(sess, "handler", None)
            try:
                if handler and hasattr(handler, "close"):
                    handler.close()
            finally:
                # Remove from registry regardless of handler.close outcome
                try:
                    del session_manager.sessions[resolved]
                except Exception:
                    pass
            return {"status": "closed", "id": resolved, "transport": "tcp"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to close TCP session: {e}")

    # Unknown/unsupported transport
    raise HTTPException(status_code=400, detail="Unknown session type")
