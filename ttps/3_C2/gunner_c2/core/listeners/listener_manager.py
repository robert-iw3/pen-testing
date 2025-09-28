import uuid
from typing import Dict, Optional

class Listener:
    def __init__(self, ip: str, port: int, transport: str, listener_id: str, profiles: Optional[str] = None):
        self.ip = ip
        self.port = port
        self.transport = transport  # e.g. "tcp", "http", "https"
        self.id = listener_id       # your random ID
        self.sessions = []          # you can append session IDs here
        self.profiles = {}      # path to .cna, if any

# global registry so you can lookup by ID from anywhere
listeners: Dict[str, Listener] = {}

socket_to_listener: Dict[int, str] = {}

def create_listener(ip: str, port: int, transport: str, profiles: Optional[str] = None) -> Listener:
    # generate an 8-char hex ID
    lid = uuid.uuid4().hex[:8]
    listener = Listener(ip, port, transport, lid, profiles)
    listeners[lid] = listener
    return listener