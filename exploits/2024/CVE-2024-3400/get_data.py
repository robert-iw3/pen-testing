from concurrent.futures import ThreadPoolExecutor
import os
import os.path
import requests
import urllib3
from urllib.parse import urlparse


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_file(url):
    a = urlparse(url)
    fname = f"out/{os.path.basename(a.path)}.tar.gz"
    if os.path.isfile(fname):
        return
    print(f"Getting {url}...")
    with requests.get(url, stream=True, verify=False, allow_redirects=False) as r:
        r.raise_for_status()
        with open(fname, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

with open('confirmed_rce.log', 'r') as f:
    targets = [t.strip() for t in f.readlines()]

with ThreadPoolExecutor(max_workers=100) as pool:
    pool.map(get_file, targets)
