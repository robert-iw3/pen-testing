from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("reg")
class RegCommand(Command):
	"""Interact with the registry: reg <query|get|set|delete> <hive>\\<path> [name data]"""

	@property
	def help(self):
		return "reg <query|get|set|delete> <hive>\\<path> [name data]    Registry operations"

	def execute(self, args):
		if len(args) < 2:
			print(brightyellow + "Usage: reg <query|get|set|delete> <hive>\\<path> [name data]")
			return
		action = args[0]
		hive_path = args[1]
		name = args[2] if len(args) >= 3 else None
		data = args[3] if len(args) >= 4 else None
		out = self.logic(self.gs.sid, self.gs.os_type, action, *hive_path.split("\\",1), name, data, op_id=self.op_id)
		if out:
			print(brightgreen + out)

	def logic(self, sid, os_type, action, hive, key_path, value_name=None, value_data=None, op_id="console"):
		"""
		Interact with the Windows registry.
		Usage:
			reg query HKLM                      # top-level
			reg query HKLM\\Software\\Foo       # a subkey
			reg get   HKLM\\Software\\Foo Name  # one value
			reg set   HKCU\\Env PATH "C:\\X"    # set a value
			reg delete HKCU\\Software\\Bad      # delete a key
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if "windows" not in os_type:
			return brightyellow + "[*] reg only supported on Windows"

		action = action.lower()
		if action not in ("query", "get", "set", "delete"):
			return brightyellow + "[*] Usage: reg <query|get|set|delete> <hive>\\<path> [<name> <data>] [/s|/f]"

		# build the native reg.exe invocation
		if action == "query":
			# if no key_path, just query the hive itself
			if key_path:
				target = f"{hive}\\{key_path}"
			else:
				target = hive
			# allow an optional flag like /s for recursive
			flag = value_name or ""
			cmd = f'reg.exe query "{target}" {flag}'.strip()

		elif action == "get":
			if not key_path or not value_name:
				return brightyellow + "[*] Usage: reg get <hive>\\<path> <ValueName>"
			cmd = f'reg.exe query "{hive}\\{key_path}" /v {value_name}'

		elif action == "set":
			if not key_path or not (value_name and value_data):
				return brightyellow + "[*] Usage: reg set <hive>\\<path> <Name> <Data>"

			cmd = (f'reg.exe add "{hive}\\{key_path}" /v {value_name} ' f'/t REG_SZ /d "{value_data}" /f')

		else:  # delete
			if not key_path:
				return brightyellow + "[*] Usage: reg delete <hive>\\<path> [/f]"
			if value_name:
				cmd = f'reg.exe delete "{hive}\\{key_path}" /v {value_name} /f'
			else:
				cmd = f'reg.exe delete "{hive}\\{key_path}" /f'

		sess = session_manager.sessions.get(sid)
		if not sess:
			return brightred + f"[!] No such session: {display}"

		if sess.transport.lower() in ("http", "https"):
			return http_exec.run_command_http(sid, cmd, op_id=op_id) or None
		else:
			return tcp_exec.run_command_tcp(sid, cmd, timeout=3.0, portscan_active=True, op_id=op_id) or None