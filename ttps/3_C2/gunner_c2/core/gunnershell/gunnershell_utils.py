import logging
logger = logging.getLogger(__name__)

from core.utils import print_gunnershell_help
from core.session_handlers import session_manager
from core.gunnershell.commands.base import COMMANDS

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

# Colorama variables
from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"
reset = Style.RESET_ALL


def help_menu(parts, to_console=True, op_id="console"):
	# help <command>
	if len(parts) == 1:
		print_gunnershell_help(parts[0])
		return True

	# help <command> <subcommand>
	elif len(parts) == 2:
		print_gunnershell_help(f"{parts[0]} {parts[1]}")
		return True

	else:
		print(brightyellow + "Usage: help or help <command> [subcommand]")
		return True

	return False

def pop_commands(gunnershell_class):
	# Expose/withdraw bofexec command based on gunnerplant
	instance = gunnershell_class
	try:
		if not instance.gunnerplant and "bofexec" in COMMANDS:
			# Remove it so get_command() can’t match it
			COMMANDS.pop("bofexec", None)
			instance._bofexec_disabled = True
			logger.debug(brightyellow + "Disabled bofexec (gunnerplant is False)" + reset)

	except Exception as e:
		logger.debug(brightred + f"Failed to conditionally disable bofexec: {e}" + reset)

# ─── Gunnerplant / BOF Helpers ──────────────────────────────────────────
def _detect_gunnerplant(gunnershell_class, op_id="console"):
	"""
	Send a simple probe to the agent. If it responds with 'specialprogram'
	(anywhere in output, case‐insensitive), set self.gunnerplant = True.
	Otherwise False.
	"""
	instance = gunnershell_class
	try:
		sess = session_manager.sessions.get(instance.sid)
		if not sess:
			instance.gunnerplant = False
			logger.debug(brightyellow + "No session found for gunnerplant probe" + reset)
			return

		cmd = "programchecktyperightnow"
		if sess.transport.lower() in ("http", "https"):
			out = http_exec.run_command_http(instance.sid, cmd, op_id=op_id)

		else:
			out = tcp_exec.run_command_tcp(instance.sid, cmd, timeout=1.5, portscan_active=True, op_id=op_id)

		text = (out or "").strip().lower()
		instance.gunnerplant = ("specialprogram" in text)
		logger.debug(brightgreen + f"Gunnerplant probe result: {instance.gunnerplant}" + reset)

	except Exception as e:
		instance.gunnerplant = False
		logger.debug(brightred + f"Gunnerplant probe error: {e}" + reset)