import subprocess
import threading
import ipaddress
import queue
import time
import json
import random
import socket
from datetime import datetime
import sys

THREADS = 100
ICMP_TIMEOUT = 1
TCP_TIMEOUT = 0.3
PORT_TO_PROBE = 80  # TCP SYN port for alternative probing

results = []
lock = threading.Lock()
processed = 0
total_hosts = 0


def icmp_ping(ip):
    """ICMP ping using system command (Linux & Mac)."""
    try:
        cmd = ["ping", "-c", "1", "-W", str(ICMP_TIMEOUT), str(ip)]
        output = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return output.returncode == 0
    except Exception:
        return False


def tcp_syn(ip):
    """Simple TCP connect scan (not full handshake)."""
    try:
        sock = socket.socket()
        sock.settimeout(TCP_TIMEOUT)
        sock.connect((str(ip), PORT_TO_PROBE))
        sock.close()
        return True
    except:
        return False


def worker(q):
    global processed
    while True:
        try:
            ip = q.get_nowait()
        except queue.Empty:
            return

        alive = False

        # Try ICMP first (quiet & simple)
        if icmp_ping(ip):
            alive = True
        else:
            # Fallback TCP SYN probe (often bypasses ICMP filters)
            if tcp_syn(ip):
                alive = True

        with lock:
            processed += 1
            if alive:
                results.append(str(ip))
                print(f"\033[92m[+] Host Up:\033[0m {ip}")

        q.task_done()


def progress_bar():
    """Simple dynamic progress bar shown while workers run."""
    while processed < total_hosts:
        percentage = (processed / total_hosts) * 100
        sys.stdout.write(f"\rProgress: {percentage:.2f}%")
        sys.stdout.flush()
        time.sleep(0.25)


def save_reports():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    # TXT
    with open(f"reports/hosts-{timestamp}.txt", "w") as f:
        for host in results:
            f.write(host + "\n")

    # JSON
    with open(f"reports/hosts-{timestamp}.json", "w") as f:
        json.dump({"alive_hosts": results}, f, indent=4)

    # Nmap list
    with open(f"reports/nmap-list-{timestamp}.txt", "w") as f:
        f.write(" ".join(results))

    print("\n\033[94mReports saved in /reports folder\033[0m")


def run_scan(network):
    global total_hosts

    # Randomize order to avoid IDS signature of sequential sweeps
    net = list(ipaddress.ip_network(network, strict=False).hosts())
    random.shuffle(net)

    total_hosts = len(net)

    q = queue.Queue()
    for ip in net:
        q.put(ip)

    # Start progress bar
    p = threading.Thread(target=progress_bar)
    p.daemon = True
    p.start()

    # Start workers
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(q,))
        t.start()
        threads.append(t)

    q.join()
    for t in threads:
        t.join()

    print("\n\n\033[92mScan Completed.\033[0m")
    save_reports()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Advanced Threaded Host Discovery Tool")
    parser.add_argument("network", help="CIDR notation, e.g., 10.0.0.0/24")

    args = parser.parse_args()
    run_scan(args.network)