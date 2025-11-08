# Makefile for SilentButDeadly
CC = cl
CFLAGS = /nologo /W4 /O2 /DNDEBUG /DWIN32_LEAN_AND_MEAN
LIBS = Fwpuclnt.lib Ws2_32.lib Ole32.lib Advapi32.lib User32.lib Shell32.lib Uuid.lib

all: SilentButDeadly.exe

SilentButDeadly.exe: SilentButDeadly.c
	$(CC) $(CFLAGS) SilentButDeadly.c /link $(LIBS)
	@echo Build completed successfully.

clean:
	@if exist *.obj del *.obj
	@if exist SilentButDeadly.exe del SilentButDeadly.exe

run: SilentButDeadly.exe
	@echo Running SilentButDeadly - make sure you're running as administrator!
	SilentButDeadly.exe

verbose: SilentButDeadly.exe
	SilentButDeadly.exe -v

continuous: SilentButDeadly.exe
	SilentButDeadly.exe -c