#!/usr/bin/env python3
import random
import requests
from bs4 import BeautifulSoup
import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode

import threading
from queue import Queue

if len(sys.argv) < 2:
    print("Usage: python3 injection.py <url_file> [cookie_string]")
    sys.exit(1)

url_file = sys.argv[1]
cookie = sys.argv[2] if len(sys.argv) > 2 else None
ua_file = "/usr/share/sqlmap/data/txt/user-agents.txt"
output_file = "reflected_output.txt"

with open(ua_file, 'r') as f:
    user_agents = [line.strip() for line in f if line.strip()]

def get_headers():
    headers = {"User-Agent": random.choice(user_agents)}
    if cookie:
        headers["Cookie"] = cookie
    return headers

with open(url_file, 'r') as f:
    urls = [line.strip() for line in f if not re.search(r'\.(css|png|jpg|jpeg|svg|gif|wolf)', line.strip(), re.IGNORECASE)]

payloads = [
    "msec",
    "<i>msec",
    '">msec',
    "'>msec",
    "';msec",
    '";msec',
    ');msec',
]

session = requests.Session()

def is_reflected(response_text, payload):
    return payload in response_text

def check_contexts(response_text, payload):
    contexts = []
    if payload in response_text:
        contexts.append("RAW HTML")

    encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
    if encoded_payload in response_text:
        contexts.append("ENCODED")

    if re.search(r'<script[^>]*>.*' + re.escape(payload) + r'.*</script>', response_text, re.DOTALL | re.IGNORECASE):
        contexts.append("JAVASCRIPT")

    attr_pattern = re.compile(r'=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']', re.IGNORECASE)
    if attr_pattern.search(response_text):
        contexts.append("HTML ATTRIBUTE")

    return contexts

def extract_js_var_line(response_text, param, payload):
    # Find the JS var assignment line containing the payload, e.g. var param = 'msec';
    pattern = re.compile(r'\bvar\s+' + re.escape(param) + r'\s*=\s*([\'"]).*?' + re.escape(payload) + r'.*?\1\s*;', re.IGNORECASE)
    match = pattern.search(response_text)
    if match:
        return match.group(0).strip()
    return None

def print_reflection(test_url):
    print(f"\033[1;91m[Vulnerable]\033[0m {test_url}")
    with open(output_file, "a") as f:
        f.write(f"[Vulnerable] {test_url}\n")

def test_param(base_url, param):
    for payload in payloads:
        params = {param: payload}
        test_url = base_url + "?" + urlencode(params)
        try:
            r = session.get(test_url, headers=get_headers(), timeout=10)
        except requests.RequestException as e:
            print(f"\033[1;31m[ERROR]\033[0m {test_url} => {e}")
            continue

        if is_reflected(r.text, payload):
            print_reflection(test_url)
            return True
    return False
    
def extract_vars_with_string_assignment(text):
    pattern = re.compile(r'\bvar\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([\'"])(.*?)\2\s*;', re.DOTALL)
    matches = pattern.findall(text)
    vars_found = [m[0] for m in matches]
    return vars_found

def extract_form_params(soup):
    params = set()
    for form in soup.find_all("form"):
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if name:
                params.add(name)
    return params

def extract_url_params_from_links(soup):
    params = set()
    for tag in soup.find_all(["a", "link", "script"]):
        url = tag.get("href") or tag.get("src")
        if url and "?" in url:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for p in qs.keys():
                params.add(p)
    return params

def worker():
    while True:
        url = q.get()
        if url is None:
            break
        try:
            r = session.get(url, headers=get_headers(), timeout=10)
            base = urlparse(url)
            base_url = base.scheme + "://" + base.netloc + base.path

            soup = BeautifulSoup(r.text, "html.parser")

            js_vars = extract_vars_with_string_assignment(r.text)
            form_params = extract_form_params(soup)
            url_params = extract_url_params_from_links(soup)
            query_params = parse_qs(base.query)

            all_params = set(js_vars) | form_params | url_params | set(query_params.keys())

            if not all_params:
                print(f"\033[1;33m[INFO]\033[0m No parameters found to test for {url}")
                q.task_done()
                continue

            reflected_any = False
            for param in all_params:
                if test_param(base_url, param):
                    reflected_any = True

            if not reflected_any:
                print(f"\033[0;37m[-]\033[0m No reflection detected for any parameter in {url}")

        except requests.RequestException as e:
            print(f"\033[1;31m[ERROR]\033[0m {url} => {e}")
        q.task_done()

# Number of threads for concurrency (adjust as needed)
num_threads = 10

q = Queue()
threads = []
for i in range(num_threads):
    t = threading.Thread(target=worker)
    t.daemon = True
    t.start()
    threads.append(t)

for url in urls:
    q.put(url)

q.join()

for i in range(num_threads):
    q.put(None)
for t in threads:
    t.join()
