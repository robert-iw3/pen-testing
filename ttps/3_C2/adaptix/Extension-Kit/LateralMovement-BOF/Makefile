
all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -o _bin/psexec.x64.o -I ./ -Os -s -c psexec/psexec.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/psexec.x64.o) && echo '[*] psexec' || echo '[X] psexec'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -o _bin/token_make.x64.o -I ./ -Os -s -c token_make/token_make.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/token_make.x64.o) && echo '[*] token_make' || echo '[X] token_make'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -o _bin/token_steal.x64.o -I ./ -Os -s -c token_steal/token_steal.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/token_steal.x64.o) && echo '[*] token_steal' || echo '[X] token_steal'
