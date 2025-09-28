# gui/api_client.py
import requests
import urllib.parse
import os

from typing import Tuple, Any, Dict

class APIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.token = None
        self.headers = {}

    # ---------- auth ----------
    def login(self, username: str, password: str):
        r = requests.post(f"{self.base_url}/auth/login", json={"username": username, "password": password})
        if r.status_code == 401:
            raise Exception("Invalid username or password")
        r.raise_for_status()
        data = r.json()
        self.token = data["token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
        # fetch self
        me = self.get_me()
        return me

    def get_me(self):
        # we can derive from token, but fetch operators list and match
        try:
            ops = self.get_operators()
            # not strictly needed; just return first admin if ours missing
        except Exception:
            ops = []
        return {"token": self.token, "role": "unknown"}

    # ---------- operators (admin) ----------
    def get_operators(self):
        r = requests.get(f"{self.base_url}/auth/operators", headers=self.headers)
        r.raise_for_status()
        return r.json()

    def create_operator(self, username: str, password: str, role: str):
        r = requests.post(f"{self.base_url}/auth/operators", headers=self.headers,
                          json={"username": username, "password": password, "role": role})
        if not r.ok:
            try:
                msg = r.json().get("detail")
            except Exception:
                msg = r.text
            raise Exception(msg)
        return r.json()

    def delete_operator(self, operator_id: str):
        r = requests.delete(f"{self.base_url}/auth/operators/{operator_id}", headers=self.headers)
        if not r.ok:
            try:
                msg = r.json().get("detail")
            except Exception:
                msg = r.text
            raise Exception(msg)
        return r.json()

    # ---------- listeners ----------
    def list_listeners(self):
        r = requests.get(f"{self.base_url}/listeners", headers=self.headers)
        r.raise_for_status()
        return r.json()

    def create_listener(self, ltype: str, bind_ip: str, port: int, profile: str|None=None):
        r = requests.post(f"{self.base_url}/listeners", headers=self.headers,
                          json={"type": ltype, "bind_ip": bind_ip, "port": port, "profile": profile})
        if not r.ok:
            try:
                raise Exception(r.json().get("detail"))
            except Exception:
                raise Exception(r.text)
        return r.json()

    def stop_listener(self, listener_id: str):
        r = requests.delete(
            f"{self.base_url}/listeners/{listener_id}",
            headers=self.headers,
            timeout=5,                      # <-- prevent GUI hang
        )
        r.raise_for_status()
        return r.json()

    # ---------- listener helpers (pure client-side shims) ----------
    def listener_can_bind(self, host: str, port: int, transport: str) -> Tuple[bool, str]:
        """
        Client-side stub so the UI can call a 'Test Bind' hook without a backend change.
        We can't test server's bindability from the GUI, so just do fast local validation
        and let the server be the source of truth on create().
        """
        try:
            port = int(port)
        except Exception:
            return False, "Port must be an integer"
        if not (1 <= port <= 65535):
            return False, "Port out of range (1-65535)"
        host = (host or "").strip()
        if not host:
            return False, "Host/IP required"
        t = (transport or "").lower()
        if t not in ("tcp", "http", "https", "tls"):
            return False, "Unknown transport"
        return True, "Looks OK (server will validate on start)"

    def listener_name_available(self, name: str) -> Tuple[bool, str]:
        """
        Optional duplicate check hook; you don’t expose a name server-side, so we
        just say OK. If later you add 'name' to the backend, update this.
        """
        return True, ""

    # New: friendly mapper used by the dialog (supports https/tls certs)
    def create_listener_v2(self, cfg: dict):
        """
        cfg keys: name (opt), transport, host, port, certfile?, keyfile?
        """
        payload = {
            "type": cfg.get("transport"),
            "bind_ip": cfg.get("host"),
            "port": int(cfg.get("port", 0)),
            "profile": None,  # unchanged; your backend ignores/uses as needed
        }

        if cfg.get("name"):
            payload["name"] = cfg["name"]

        # Pass-through TLS bits if backend supports them
        if cfg.get("transport") in ("https", "tls"):
            if "certfile" in cfg:
                payload["certfile"] = cfg["certfile"]
            if "keyfile" in cfg:
                payload["keyfile"] = cfg["keyfile"]
        r = requests.post(f"{self.base_url}/listeners", headers=self.headers, json=payload)
        if not r.ok:
            try:
                raise Exception(r.json().get("detail"))
            except Exception:
                raise Exception(r.text)
        return r.json()

    # ---------- sessions ----------
    def list_sessions(self):
        r = requests.get(f"{self.base_url}/sessions", headers=self.headers)
        r.raise_for_status()
        return r.json()

    def get_session(self, sid: str):
        """Fetch one session (for title/metadata lookups)."""
        r = requests.get(f"{self.base_url}/sessions/{sid}", headers=self.headers)
        r.raise_for_status()
        return r.json()

    def exec_once(self, sid: str, cmd: str):
        r = requests.post(f"{self.base_url}/sessions/{sid}/exec", headers=self.headers, params={"cmd": cmd})
        r.raise_for_status()
        return r.json().get("output","")

    def kill_session(self, sid: str):
        """
        Best-effort kill endpoint. If your backend uses a different route,
        adjust here (e.g. DELETE /sessions/{sid}).
        """
        url = f"{self.base_url}/sessions/{sid}/kill"
        r = requests.post(url, headers=self.headers)
        if not r.ok:
            raise Exception(r.json().get("detail", r.text))
        return r.json()

    # ---------- files (remote) ----------
    def list_dir(self, sid: str, path: str):
        r = requests.get(f"{self.base_url}/files", headers=self.headers, params={"sid": sid, "path": path})
        r.raise_for_status()
        return r.json()

    def download_file(self, sid: str, remote_path: str, local_path: str):
        with requests.get(f"{self.base_url}/files/download", headers=self.headers, params={"sid": sid, "path": remote_path}, stream=True) as r:
            r.raise_for_status()
            with open(local_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        return local_path

    def upload_file(self, sid: str, local_path: str, remote_path: str):
        with open(local_path, "rb") as fp:
            files = {"file": (os.path.basename(local_path), fp, "application/octet-stream")}
            r = requests.post(f"{self.base_url}/files/upload", headers=self.headers, params={"sid": sid, "path": remote_path}, files=files)
        if not r.ok:
            try:
                raise Exception(r.json().get("detail"))
            except Exception:
                raise Exception(r.text)
        return r.json()

    # ---------- payload helpers ----------
    def gen_win_ps1(self, transport: str, host: str, port: int, beacon: int=5) -> str:
        r = requests.get(f"{self.base_url}/payloads/windows/ps1", headers=self.headers,
                         params={"transport": transport, "host": host, "port": port, "beacon": beacon})
        r.raise_for_status()
        return r.text

    def gen_linux_bash(self, transport: str, host: str, port: int) -> str:
        r = requests.get(f"{self.base_url}/payloads/linux/bash", headers=self.headers,
                         params={"transport": transport, "host": host, "port": port})
        r.raise_for_status()
        return r.text

    # ---------- New, unified payload API ----------
    def generate_windows_payload(self, cfg: Dict) -> str:
        """
        Keys: format(ps1|exe|gunnerplant), transport(tcp|tls|http|https), host, port,
              obs?, no_child?, beacon?, jitter?, headers?, useragent?, accept?, byte_range?,
              profile?, stager_ip?, stager_port?
        """
        r = requests.post(f"{self.base_url}/payloads/windows", headers=self.headers, json=cfg, timeout=180)
        if not r.ok:
            try:
                raise Exception(r.json().get("detail"))
            except Exception:
                raise Exception(r.text)
        return r.text

    def generate_linux_payload(self, cfg: Dict) -> str:
        """
        Keys: format('bash'), transport(tcp|http), host, port, obs?, beacon?, use_ssl?
        """
        r = requests.post(f"{self.base_url}/payloads/linux", headers=self.headers, json=cfg, timeout=180)
        if not r.ok:
            try:
                raise Exception(r.json().get("detail"))
            except Exception:
                raise Exception(r.text)
        return r.text
