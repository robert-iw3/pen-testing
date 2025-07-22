all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c quser/quser.c -o _bin/quser.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/quser.x64.o) && echo '[*] quser' || echo '[X] quser'
