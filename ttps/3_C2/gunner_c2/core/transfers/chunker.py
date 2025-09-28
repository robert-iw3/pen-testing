import os, math
from typing import Tuple

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

def chunk_count(total_bytes: int, chunk: int) -> int:
    return (total_bytes + chunk - 1) // chunk

def index_to_offset(index: int, chunk: int) -> int:
    return index * chunk

def human_bytes(n: int) -> str:
    units = ["B","KB","MB","GB","TB"]
    x = float(n)
    for u in units:
        if x < 1024 or u == units[-1]:
            return f"{x:.1f} {u}"
        x /= 1024.0

def ensure_prealloc(path: str, size: int) -> None:
    """
    Ensure the .part file exists; sparse pre-allocate to 'size' if supported.
    """
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            pass
    # Best-effort sparse extend
    with open(path, "r+b") as f:
        try:
            if size > 0:
                f.seek(size - 1)
                f.write(b"\0")
        except Exception:
            # ignore on FS that doesn't support sparse/truncation like this
            pass

def write_at(path: str, offset: int, data: bytes) -> None:
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(data)