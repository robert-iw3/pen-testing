# backend/listeners.py
from fastapi import APIRouter, HTTPException
from typing import Dict
import threading

from core.listeners.base import load_listeners, create_listener
from .schemas import NewListenerRequest, ListenerOut

router = APIRouter()

load_listeners()
_RUNNING: Dict[str, object] = {}

ALLOWED_TYPES = {"tcp", "http", "https", "tls"}

def _serialize_listener(inst) -> ListenerOut:
    return {
        "id": getattr(inst, "id", ""),
        "type": getattr(inst, "transport", ""),
        "bind_ip": getattr(inst, "ip", ""),
        "port": getattr(inst, "port", 0),
        "status": "RUNNING"
            if getattr(inst, "thread", None) and getattr(inst.thread, "is_alive", lambda: False)()
            else "STARTED",
        "profile": getattr(inst, "profiles", None) or None,
        "name": getattr(inst, "name", None),
    }

@router.get("", response_model=list[ListenerOut])
def list_listeners():
    return [_serialize_listener(inst) for inst in _RUNNING.values()]

@router.post("", response_model=ListenerOut)
def start_listener(req: NewListenerRequest):
    t = (req.type or "").lower().strip()
    if t not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported listener type '{t}'")

    if not req.name:
        raise HTTPException(status_code=400, detail=f"Listener name must be provided!")

    # Optional friendly name: reject duplicates if provided
    friendly = (req.name or "").strip()
    if friendly and any(getattr(x, "name", "") == friendly for x in _RUNNING.values()):
        raise HTTPException(status_code=400, detail=f"Listener name '{friendly}' already in use")

    kwargs = {"profiles": req.profile}
    if t in ("https", "tls"):  # optional TLS bits
        if req.certfile: kwargs["certfile"] = req.certfile
        if req.keyfile:  kwargs["keyfile"]  = req.keyfile

    try:
        inst = create_listener(req.bind_ip, req.port, t, **kwargs)
    except TypeError:
        # core without cert/key params
        inst = create_listener(req.bind_ip, req.port, t, profiles=req.profile)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to start listener: {e}")

    lid = getattr(inst, "id", "") or ""
    if not lid:
        raise HTTPException(status_code=500, detail="Listener missing ID")

    # Attach the friendly name (fall back to transport:port)
    try:
        inst.name = friendly or f"{t}:{req.port}"
    except Exception:
        pass

    _RUNNING[lid] = inst
    return _serialize_listener(inst)

def _stop_instance_async(inst):
    """Call the best-effort stop method without blocking the request thread."""
    for attr in ("stop", "shutdown", "close"):
        fn = getattr(inst, attr, None)
        if callable(fn):
            try:
                fn()
            except Exception:
                pass
            break

@router.delete("/{listener_id}")
def stop_listener(listener_id: str):
    inst = _RUNNING.get(listener_id)
    if not inst:
        raise HTTPException(status_code=404, detail="Listener not found")

    # Fire-and-detach a daemon thread to stop the instance.
    done = threading.Event()
    def worker():
        try:
            _stop_instance_async(inst)
        finally:
            done.set()

    threading.Thread(target=worker, daemon=True).start()

    # Wait briefly so fast stops can report 'stopped'
    finished = done.wait(timeout=2.0)
    # Remove from registry immediately so the UI no longer shows it
    _RUNNING.pop(listener_id, None)

    return {"status": "stopped" if finished else "stopping", "id": listener_id}
