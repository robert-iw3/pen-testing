import requests
import threading
import queue
import time
import json
import random
import sys
from urllib.parse import urljoin
from datetime import datetime

# ------------------------------
# Global Configurations
# ------------------------------
THREADS = 30
TIMEOUT = 5
RETRIES = 3
THROTTLE_MIN = 0.05
THROTTLE_MAX = 0.20

results = []
lock = threading.Lock()
print_lock = threading.Lock()
total_words = 0
processed = 0


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)",
]


def fingerprint(response):
    """Return a small fingerprint based on status + length."""
    length = len(response.content)
    return f"{response.status_code}-{length}"


def fetch(session, url, retries=0):
    """Send GET request with retry + dynamic throttling."""
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}

        response = session.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=False)

        # small random sleep to avoid hitting server aggressively
        time.sleep(random.uniform(THROTTLE_MIN, THROTTLE_MAX))

        return response

    except requests.RequestException:
        if retries < RETRIES:
            return fetch(session, url, retries + 1)
        return None


def worker(base_url, q):
    global processed

    session = requests.Session()

    while True:
        try:
            path = q.get_nowait()
        except queue.Empty:
            return

        full_url = urljoin(base_url, path)

        response = fetch(session, full_url)

        with lock:
            processed += 1

        if response and response.status_code not in [404, 400]:
            # Important fingerprinting info
            fp = fingerprint(response)
            status = response.status_code
            length = len(response.content)

            with lock:
                results.append({
                    "path": path,
                    "status": status,
                    "length": length,
                    "fingerprint": fp
                })

            with print_lock:
                print(f"\033[92m[FOUND]\033[0m {status} | {length} bytes | /{path}")

        q.task_done()


def progress_bar():
    """Simple progress indicator."""
    while processed < total_words:
        percent = (processed / total_words) * 100
        sys.stdout.write(f"\rProgress: {percent:.2f}%")
        sys.stdout.flush()
        time.sleep(0.2)


def save_reports():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Sort result by status + length clusters
    sorted_res = sorted(results, key=lambda x: (x["status"], x["length"]))

    # --- Save TXT ---
    with open(f"reports/results-{timestamp}.txt", "w") as f:
        for r in sorted_res:
            f.write(f"{r['status']} - {r['length']} bytes - /{r['path']}\n")

    # --- Save JSON ---
    with open(f"reports/results-{timestamp}.json", "w") as f:
        json.dump(sorted_res, f, indent=4)

    # --- Save HTML report ---
    html = """
    <html>
    <head>
        <title>Directory Bruteforce Report</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { padding: 8px 12px; border: 1px solid #ccc; }
            th { background: #333; color: white; }
        </style>
    </head>
    <body>
        <h2>Directory Bruteforce Report</h2>
        <table>
        <tr><th>Status</th><th>Length</th><th>Path</th><th>Fingerprint</th></tr>
    """

    for r in sorted_res:
        html += f"<tr><td>{r['status']}</td><td>{r['length']}</td><td>/{r['path']}</td><td>{r['fingerprint']}</td></tr>"

    html += "</table></body></html>"

    with open(f"reports/results-{timestamp}.html", "w") as f:
        f.write(html)

    print(f"\n\033[94mReports saved in /reports folder\033[0m")


def run_bruteforce(base_url, wordlist):
    global total_words

    if not base_url.endswith("/"):
        base_url += "/"

    q = queue.Queue()

    with open(wordlist, "r") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]

    for l in lines:
        q.put(l)

    total_words = len(lines)

    # Progress bar
    t = threading.Thread(target=progress_bar)
    t.daemon = True
    t.start()

    # Start threads
    threads = []
    for _ in range(THREADS):
        th = threading.Thread(target=worker, args=(base_url, q))
        th.start()
        threads.append(th)

    q.join()

    for th in threads:
        th.join()

    print("\n\n\033[92mScan Completed.\033[0m")
    save_reports()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Advanced Directory Bruteforcer")
    parser.add_argument("url", help="Target base URL")
    parser.add_argument("wordlist", help="Path to wordlist")

    args = parser.parse_args()
    run_bruteforce(args.url, args.wordlist)