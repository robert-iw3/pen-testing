from core.gunnershell.commands.base import register, Command
from core import shell
from core.session_handlers import session_manager

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec


from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"

import subprocess
import shutil
import os, sys
import tempfile

@register("edit")
class EditCommand(Command):
	"""Download, edit, and re-upload a file: edit <path>"""

	@property
	def help(self):
		return "edit <path>    Download, edit, and re-upload a remote file"

	def execute(self, args):
		if len(args) != 1:
			print(brightgreen + "Usage: edit <path>")
			return
		path = args[0]
		path = self.gs.make_abs(path)
		result = self.logic(self.gs.sid, self.gs.os_type, path, op_id=self.op_id)
		print(brightgreen + result)

	def logic(self, sid, os_type, remote_path, op_id="console"):
		"""
		Download a remote file, verify it’s text, open it in $EDITOR (or nano), then re-upload it.
		Returns a status message.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		sess = session_manager.sessions.get(sid)
		if not sess:
			return f"[!] No such session: {display}"

		# choose download/upload functions
		if sess.transport.lower() in ("http", "https"):
			dl = shell.download_file_http
			shell.upload_file_http

		elif sess.transport.lower() in ("tcp", "tls"):
			dl = shell.download_file_tcp
			ul = shell.upload_file_tcp

		else:
			print(brightred + f"[!] Unsupported session type {display}")
			return None

		# create a temp file
		fname = os.path.basename(remote_path)
		fd, local_tmp = tempfile.mkstemp(prefix="gunner-edit-", suffix="-"+fname)
		os.close(fd)

		# download the remote file
		try:
			dl(sid, remote_path, local_tmp)

		except Exception as e:
			os.remove(local_tmp)
			return f"[!] Failed to download {remote_path}: {e}"

		# quick "is-text" sniff: look for any NUL byte in the first 8KiB
		try:
			with open(local_tmp, "rb") as f:
				sample = f.read(8192)

			if b"\x00" in sample:
				os.remove(local_tmp)
				return "[!] File appears to be binary, edit aborted"

		except Exception as e:
			os.remove(local_tmp)
			return f"[!] Couldn’t read temp file: {e}"

		# launch your editor
		# pick a local editor by probing common names
		editors = ["nano", "vim", "vi", "code", "notepad"]  # adjust to taste
		for ed in editors:
			if shutil.which(ed):
				editor = ed
				break
		else:
			os.remove(local_tmp)
			return "[!] No editor found (tried: {})".format(", ".join(editors))

		# launch the chosen editor
		try:
			subprocess.call([editor, local_tmp])

		except Exception as e:
			os.remove(local_tmp)
			return f"[!] Failed to launch editor ({editor}): {e}"

		# re-upload
		try:
			ul(sid, local_tmp, remote_path)

		except Exception as e:
			os.remove(local_tmp)
			return f"[!] Failed to re-upload {remote_path}: {e}"

		# cleanup & done
		os.remove(local_tmp)
		return f"Edited and re-uploaded {remote_path}"