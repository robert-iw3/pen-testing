# GunnerC2

![1758820780591](https://github.com/user-attachments/assets/0e94810a-3764-4b3e-bf0a-216dc3c8083b)


A modern, operator-friendly **Command-and-Control framework** for authorized red-team operations and research.  
GunnerC2 blends a beautiful GUI, a powerful shell, and a modular core to make day-to-day ops fast, visual, and collaborative.

> **Legal / Ethics**  
> GunnerC2 is for **authorized use only**—training, research, and engagements with **explicit written consent**. You are responsible for compliance with all laws and agreements.

---

## 🔐 Defaults (read me first)

- **Default credentials:** `gunner:admin`  
- **Teamserver default port:** **6060**

---

## 🚀 Why GunnerC2?

- **One tool, full stack:** Listeners, payloads, session control, file ops, BOFs, teamserver—**tightly integrated**.
- **Operator speed:** A crisp GUI + a **powerful built-in GunnerShell** for instant flow.
- **Visual awareness:** A live **Session Graph** and first-class File/LDAP browsers keep context at your fingertips.
- **Enterprise-style coordination:** **Multi-operator support**, teamserver, and **role-based access control**.

---

## ✨ Feature Highlights

- **Listeners:** **TCP, TLS, HTTP, HTTPS**
- **Payloads:** Linux & Windows
- **Formats:** **bash**, **ps1**, **exe** for **all protocols**
- **Shell:** **GunnerShell** (fast, helpful, OP-friendly)
- **Custom Implant:** **GunnerPlant** with integrated **BOF loader**
- **BOF Library:** **95+ BOFs** ready to go
- **OPSEC:** **Malleable C2 profiles**
- **GUI:** Beautiful PyQt interface with **File Browser** & **LDAP Browser**
- **Situational Awareness:** **Session Graph**
- **Remote Editing:** Built-in **text editor** for remote files
- **File Ops:** **Resumable uploads & downloads** (files & folders)
- **Collaboration:** **Teamserver**, **multi-operator**, **RBAC**

---

## ⚙️ Install

**Requirements**
- Python **3.9–3.12** (3.11 recommended)
- `pip` installed
- (Linux GUI) system libs: `libxcb-xinerama0` and `libxkbcommon-x11-0`

**Clone & install deps**
```bash
https://github.com/LeighlinRamsay/GunnerC2.git
cd GunnerC2
python3 -m pip install -r requirements.txt

sudo apt-get update
sudo apt-get install -y libxcb-xinerama0 libxkbcommon-x11-0
```

**Troubleshooting module not found**
```bash
touch core/__init__.py
touch backend/__init__.py
touch gui/__init__.py
```

**Using GunnerC2**
```bash
python3 main.py
python3 gui/main.py
```
---
