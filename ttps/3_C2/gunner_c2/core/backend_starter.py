# === Backend API auto-starter (paste near your imports in main.py) ===
import os, sys, threading, socket, time

def _is_listening(host: str, port: int, timeout: float = 0.2) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        try: s.close()
        except Exception: pass

def ensure_backend_running(host: str | None = None, port: int | None = None) -> str:
    """
    Start the FastAPI backend (backend.main:app) inside this process via uvicorn,
    in a daemon thread. If the port is already in use, we assume it's running.
    Returns the base URL, e.g. "http://127.0.0.1:8000".
    """
    host = host or os.environ.get("GUNNER_BACKEND_HOST", "127.0.0.1")
    port = int(port or os.environ.get("GUNNER_BACKEND_PORT", "6060"))
    base_url = f"http://{host}:{port}"

    # If already up, don't start another.
    if _is_listening(host, port):
        print(f"[+] Backend already listening at {base_url}")
        return base_url

    # Make sure we can import the ASGI app
    try:
        # Ensure project root (where backend/ and core/ live) is on sys.path
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        from backend.main import app as _backend_app  # FastAPI instance
    except Exception as e:
        print(f"[!] Could not import backend.main: {e}")
        raise

    # Spin up uvicorn in a background thread
    try:
        import uvicorn
    except ImportError:
        raise RuntimeError(
            "uvicorn is not installed. Install with: pip install uvicorn fastapi"
        )

    def _run():
        try:
            config = uvicorn.Config(
                app=_backend_app,
                host=host,
                port=port,
                log_level=os.environ.get("GUNNER_BACKEND_LOGLEVEL", "warning"),
                access_log=False,
            )
            server = uvicorn.Server(config)
            # Avoid signal handler setup outside main thread
            try:
                server.install_signal_handlers = lambda: None  # type: ignore[attr-defined]
            except Exception:
                pass
            server.run()
        except Exception as ex:
            print(f"[!] Backend server crashed: {ex}")

    t = threading.Thread(target=_run, name="gunner-backend-uvicorn", daemon=True)
    t.start()

    # Briefly wait until the socket opens (non-blocking overall)
    for _ in range(40):  # ~4s worst-case
        if _is_listening(host, port):
            #print(f"[+] Backend started at {base_url}")
            break
        time.sleep(0.1)

    return base_url
