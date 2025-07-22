all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -c -o _bin/getsystem_token.x64.o getsystem_token/getsystem_token.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/getsystem_token.x64.o) && echo '[*] getsystem_token' || echo '[X] getsystem_token'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -c -o _bin/uac_regshellcmd.x64.o uac_regshellcmd/RegistryShellCommandBOF.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/uac_regshellcmd.x64.o) && echo '[*] uac_regshellcmd' || echo '[!] uac_regshellcmd build failed'
	@(x86_64-w64-mingw32-gcc -w -Os -s -c -o _bin/uac_sspi.x64.o uac_sspi/SspiUacBypassBOF.cpp && x86_64-w64-mingw32-strip --strip-unneeded _bin/uac_sspi.x64.o) && echo '[*] uac_sspi' || echo '[!] uac_sspi build failed'
