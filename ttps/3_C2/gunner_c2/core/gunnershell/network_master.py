import ntpath
import os
import sys
import subprocess
import re
import time
import ipaddress
import threading, socketserver, socket
from core.session_handlers import session_manager
from core import shell
from core.listeners import tcp
from core import print_override
import _thread
import base64
import queue
from itertools import chain, cycle


# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

# Colorama Settings
from colorama import Style, Fore
brightgreen = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred   = Style.BRIGHT + Fore.RED
brightcyan  = Style.BRIGHT + Fore.CYAN
reset = Style.RESET_ALL

def hostname(sid, os_type, op_id="console"):
	"""
	Display the remote host's hostname.
	"""
	# resolve display alias

	if os_type not in ("windows", "linux"):
		return brightred + "[!] Unsupported operating system on agent!"

	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
	cmd = "hostname"

	sess = session_manager.sessions.get(sid)
	if not sess:
		return brightred + f"[!] No such session: {display}"

	transport = sess.transport.lower()
	if transport in ("http", "https"):
		out = http_exec.run_command_http(sid, cmd, op_id=op_id)
	
	elif transport in ("tcp", "tls"):
		out =  tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

	else:
		return brightred + "[!] Unknown session transport!"

	if out:
		return out
