# core/sessions.py

import queue
import socket
import random
import string
import sys

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

PROMPT = brightblue + "GunnerC2 > "

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.output_queue = queue.Queue()
        self.tcp_listener_sockets = {}

    def gen_session_id(self):
        parts = []
        for _ in range(3):
            parts.append(''.join(random.choices(string.ascii_lowercase + string.digits, k=5)))
        return '-'.join(parts)

    def register_http_session(self, sid):
        if sid not in self.sessions:
            self.sessions[sid] = queue.Queue()
            print(brightgreen + f"\n[+] New HTTP agent: {sid}")
            sys.stdout.write(PROMPT)
            sys.stdout.flush()

    def register_tcp_session(self, client_socket):
        sid = self.gen_session_id()
        self.sessions[sid] = client_socket
        print(brightgreen + f"\n[+] New TCP agent: {sid}")
        sys.stdout.write(PROMPT)
        sys.stdout.flush()
        return sid

    def close_all_tcp_listeners(self):
        for name, sock in self.tcp_listener_sockets.items():
            try:
                sock.close()
                print(brightyellow + f"Closed listener {name}")
            except:
                pass