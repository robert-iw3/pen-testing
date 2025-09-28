import logging
logger = logging.getLogger(__name__)

import os
import sys
import argparse
from abc import ABC, abstractmethod
import pkgutil
import importlib

class QuietParser(argparse.ArgumentParser):
	def error(self, message):
		raise SystemExit

# ─── Command Base ───────────────────────────────────────────────────────────
class Command(ABC):
	"""
	Base class for all Gunnershell commands.
	Subclasses MUST implement `execute(self, args: list[str])`.
	"""
	def __init__(self, gs, to_console: bool, op_id: str):
		self.gs         = gs
		self.to_console = to_console
		self.op_id      = op_id

	@abstractmethod
	def execute(self, args: list[str]):
		"""Run the command with the given args."""

	@abstractmethod
	def logic(self, *args, **kwargs):
		"""
		Core logic for this command.
		Subclasses may define any signature they like, e.g.

			def logic(self, path):                # for ls, cat, cd…
			def logic(self, host, port, flag):    # for portscan, etc.

		The base definition here just enforces that
		every Command subclass implements a `logic`.
		"""

COMMANDS: dict = {}

def register(*names: str):
    """
    Decorator to register a Command subclass under one or more names,
    including multi‐word names like "netexec smb".
    """
    def deco(cls):
        for name in names:
            parts = name.split()
            node = COMMANDS
            # for every segment except the last, descend/create sub‐dict
            for seg in parts[:-1]:
                node = node.setdefault(seg, {})
            # final segment maps to the class
            node[parts[-1]] = cls
        return cls
    return deco

def get(parts: list[str]):
    """
    Given the tokenized user input, find the longest matching
    entry in COMMANDS, return (CommandClass, consumed_count).
    """
    node = COMMANDS
    match = None
    consumed = 0
    for i, seg in enumerate(parts):
        if not isinstance(node, dict) or seg not in node:
            break
        node = node[seg]
        consumed = i + 1
        # if node is a class (leaf), record it
        if isinstance(node, type):
            match = node
            # keep going in case there's a deeper (multi‐word) command 
        elif "__default__" in node and match is None:
            # optional: handle default for a multi‐command group
            match = node["__default__"]
    return match, consumed

def list_commands() -> list[str]:
	"""
	Return a sorted list of all registered command names.
	"""
	return sorted(COMMANDS.keys())


def load(os_type: str | None = None):
    """
    Import command modules so that @register() hooks populate COMMANDS.
    Layout supported:
      core/gunnershell/commands/common/...
      core/gunnershell/commands/windows/...
      core/gunnershell/commands/linux/...
    If os_type is provided, only that subtree (+ common) is imported.
    """
    # import the commands package itself so we can grab its __path__
    pkg = importlib.import_module(__package__)  # __package__ == "core.gunnershell.commands"

    target = (os_type or "").lower()
    for _, module_name, is_pkg in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
        # skip our own base module
        if module_name == pkg.__name__ + ".base":
            continue

        # Filter by OS subtree unless it's common
        if ".windows." in module_name and target and "win" not in target:
            continue
        if ".linux." in module_name and target and "linux" not in target:
            continue
        if ".common." in module_name or ".windows." in module_name or ".linux." in module_name or module_name.count(".") >= 4:
            pass  # allowed
        # else allow legacy modules at the top until everything is moved

        logger.debug(f"Loading command module {module_name}")
        try:
            importlib.import_module(module_name)

        except Exception:
            logger.exception("Failed to import command module %r", module_name)

def connection_builder(dc_ip=None, domain=None):
    if dc_ip and not domain:
        dns_preamble = f"""
$T = '{dc_ip}'
try {{
    $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
}} catch {{
    $nb = $T
}}
"""
    
    if dc_ip and domain:
        dns_preamble = f"""

try {{
    $domain = '{domain}'
    try {{
    $nb = (Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$domain" | Sort-Object Priority,Weight | Select-Object -First 1).NameTarget.TrimEnd('.')
    }} catch {{ 
            $T = '{dc_ip}'
            try {{
            $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
        }} catch {{
            $nb = $T
        }}  
    }}
}} catch {{
    Write-Output "Failed to resolve DC!"
    break
}}
"""
    
    if domain:
        dns_preamble = f"""

$domain = '{domain}'
try {{
$nb = (Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$domain" | Sort-Object Priority,Weight | Select-Object -First 1).NameTarget.TrimEnd('.')
}} catch {{ 
            Write-Output "Failed to resolve DC!"
            break
}}
"""
    
    if dns_preamble:
        return dns_preamble

    else:
        return "ERROR"