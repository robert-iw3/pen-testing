import socket
from core import session_manager, utils
import os,sys,subprocess
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import tempfile

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

PROMPT = brightblue + "GunnerC2 > "


def generate_tls_context():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"GunnerC2")
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

    # Write to temporary files
    key_file = tempfile.NamedTemporaryFile(delete=False)
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    key_file.write(key_bytes)
    cert_file.write(cert_bytes)
    key_file.close()
    cert_file.close()

    # Load into SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
    return context

def collect_tcp_metadata(sid):
    session = session_manager.sessions[sid]
    sock = session.handler

    try:
        # Step 1: OS Detection via uname -a
        sock.sendall(b"uname\n")
        sock.settimeout(2)
        response = b""

        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        output = response.decode(errors="ignore").strip()
        #print(f"[DEBUG] TCP agent {sid} OS check: {output}")
        session.detect_os(output)

        # Step 2: Queue and collect metadata
        for field, cmd in session.os_metadata_commands:
            try:
                sock.sendall((cmd + "\n").encode())
                sock.settimeout(2)
                response = b""

                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break

                result = response.decode(errors="ignore").strip()
                lines = [line for line in result.splitlines() if line.strip() not in ("$", "#", ">")]
                result_cleaned = "\n".join(lines).strip()
                session.metadata[field] = result_cleaned

            except Exception as e:
                print(brightred + f"[!] Metadata collection failed for {sid} (field: {field}): {e}")
                session.metadata[field] = "Error"

    except Exception as e:
        print(brightred + f"[!] OS detection failed for {sid}: {e}")
        session.metadata["os"] = "Unknown"

def start_tcp_listener(ip, port):
    print(brightyellow + f"[+] TCP listener started on {ip}:{port}")
    context = generate_tls_context()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    utils.tcp_listener_sockets[f"tcp-{ip}:{port}"] = server_socket

    while True:
        raw_client, addr = server_socket.accept()

        try:
            client_socket = context.wrap_socket(raw_client, server_side=True)

        except Exception as e:
            print(brightred + f"[-] TLS handshake failed from {addr}: {e}")
            continue

        sid = utils.gen_session_id()
        session_manager.register_tcp_session(sid, client_socket)

        print(brightgreen + f"\n[+] New TCP agent: {sid}\n")
        sys.stdout.write(PROMPT)
        sys.stdout.flush()

        # DRAIN BANNER (important!)
        client_socket.settimeout(0.5)
        try:
            while True:
                junk = client_socket.recv(1024)
                if not junk:
                    break
        except:
            pass
        client_socket.settimeout(None)

        collect_tcp_metadata(sid)
