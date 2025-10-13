import ssl
import threading
from http.server import HTTPServer
from socketserver import ThreadingMixIn
import os, sys, subprocess
from core.listeners.http_handler import C2HTTPRequestHandler, generate_http_session_id
from core.listeners.tcp_listener import generate_tls_context
from core.prompt_manager import prompt_manager
from core.listeners.base import create_listener, socket_to_listener
from core.print_override import set_output_context
from core import utils
from colorama import init, Fore, Style

brightgreen  = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred    = Style.BRIGHT + Fore.RED

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

def start_https_listener(ip: str, port: int, certfile: str = None, keyfile: str = None, to_console=True, op_id=None):
    if to_console:
        set_output_context(to_console=True)
        print_type = "console"

    elif op_id:
        set_output_context(to_console=False, to_op=op_id)
        print_type = "operator"

    try:
        print(brightyellow + f"[+] HTTPS listener starting on {ip}:{port}")
        # Create the HTTP server
        httpd = ThreadingHTTPServer((ip, port), C2HTTPRequestHandler)
        utils.https_listener_sockets[f"https-{ip}:{port}"] = httpd
        listener_obj = create_listener(ip, port, "https")
        socket_to_listener[ httpd.socket.fileno() ] = listener_obj.id

        httpd.scheme = "https"

        prompt_manager.get_prompt()
        # Build or load TLS context
        if certfile and keyfile:
            if not (os.path.isfile(certfile) and os.path.isfile(keyfile)):
                prompt_manager.block_next_prompt = False
                print(brightred + "[!] Cert or key file not found, aborting HTTPS listener.")
                return

            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            print(brightgreen + f"[*] Loaded certificate {certfile} and key {keyfile}")

        else:
            context = generate_tls_context(ip)
            print(brightgreen + "[*] Using generated self-signed certificate")

        # Wrap the HTTPServer socket
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        prompt_manager.block_next_prompt = False
        print(brightgreen + f"[+] HTTPS listener ready on {ip}:{port}")
        try:
            httpd.serve_forever()

        except (KeyboardInterrupt, SystemExit):
            httpd.shutdown()
            print(brightyellow + "[*] HTTPS listener stopped")

        except (ConnectionResetError, BrokenPipeError):
            print(brightred + f"[!] Connection reset from one of your agents!")

    except (ConnectionResetError, BrokenPipeError):
        prompt_manager.block_next_prompt = False
        print(brightred + f"[!] Connection reset from one of your agents!")

    except Exception as e:
        prompt_manager.block_next_prompt = False
        print(brightred + f"[!] An unknown error has ocurred in your HTTPS listener: {e}")
