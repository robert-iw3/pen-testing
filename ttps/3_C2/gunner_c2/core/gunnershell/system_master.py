import os
import sys
import subprocess
import argparse
import threading
import textwrap
import base64
import struct
from http.server import HTTPServer, BaseHTTPRequestHandler
from core.session_handlers import session_manager
from core import shell


# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from core.payload_generator.payload_generator import *
from core.malleable_c2 import malleable_c2 as malleable


# Colorama Settings
from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
COLOR_RESET  = "\001\x1b[0m\002"
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"

PROMPT = f"{UNDERLINE_ON}{brightblue}GunnerShell{UNDERLINE_OFF} > "