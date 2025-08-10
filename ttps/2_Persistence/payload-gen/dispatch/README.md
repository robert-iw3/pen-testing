# Dispatch – Evasive Payload Delivery Server

## Overview  
**Dispatch** is an **evasive payload delivery server** built for **penetration testers, red teamers, CTFs, and more**! Dispatch enables **secure, dynamic payload delivery** that actively evades detection, making it difficult for defenders to track and intercept.  

With **built-in evasion techniques**, **custom alias addresses**, and a **reverse proxy for C2 traffic**, Dispatch provides a **powerful yet lightweight** solution for modern offensive security professionals.  

#### Features:  
- **Payload Access Control** – Prevent unauthorized downloads by IP, device, or secret keys invoking an external redirect. 
- **Smart File Permissions** – Set payloads as public, private, or one-time use.  
- **User & Role Management** – Assign roles to control team access.  
- **Instant Download Cradles** – Generate ready-to-use commands in the admin portal.  
- **Simple File Uploads** – Use the web interface to upload files or automate using the Dispatch API

<img height="400" alt="dispatch" src="https://github.com/user-attachments/assets/c6ec329b-933d-4560-a3e8-2eeb74095b22" />


## ⚡ Install  
Dispatch is designed for **Windows, Linux, and macOS** with minimal dependencies. Simply, execute the following commands to get started:  

```bash
sudo sysctl net.ipv4.ip_unprivileged_port_start=443
# to undo: sudo sysctl net.ipv4.ip_unprivileged_port_start=1024

podman build -t dispatch .

podman run -it --name dispatch \
    --cap-add=net_admin \
    --device /dev/net/tun \
    -v /etc/resolv.conf:/etc/resolv.conf:ro \
    -p 127.0.0.1:443:443 -p 127.0.0.1:8118:8118 -p 127.0.0.1:9050:9050 -p 127.0.0.1:9051:9051 \
    -d dispatch

podman exec dispatch python3 dispatch-server.py

# https://0.0.0.0:443/
```


## ▶️ Usage
All documentation, including user roles, API integrations, and detailed access controls are available in the Web UI.

### Python
Launch the Dispatch server with:
```bash
pip3 install -r requirements.txt
python3 dispatch-server.py
```

### Poetry
Alternatively, install with Poetry and execute using the `dispatch` run command:
```bash
python3 -m poetry run dispatch
```


## ⚠️ Disclaimer
Dispatch is intended for authorized security testing. Never test against systems you don’t own or have explicit permission.
