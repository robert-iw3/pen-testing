all: bof

clean:
	@(rm -f _bin/* && echo '[*] cleaned')

bof:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[*] _bin exists'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c arp/arp.c -o _bin/arp.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/arp.x64.o) && echo '[*] arp' || echo '[X] arp'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c cacls/cacls.c -o _bin/cacls.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/cacls.x64.o) && echo '[*] cacls' || echo '[X] cacls'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c dir/dir.c -o _bin/dir.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/dir.x64.o) && echo '[*] dir' || echo '[X] dir'
	@(x86_64-w64-mingw32-gcc -I _include -Os -s -c env/env.c -o _bin/env.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/env.x64.o) && echo '[*] env' || echo '[X] env'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c ipconfig/ipconfig.c -o _bin/ipconfig.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/ipconfig.x64.o) && echo '[*] ipconfig' || echo '[X] ipconfig'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c listdns/listdns.c -o _bin/listdns.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/listdns.x64.o) && echo '[*] listdns' || echo '[X] listdns'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c netstat/netstat.c -o _bin/netstat.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/netstat.x64.o) && echo '[*] netstat' || echo '[X] netstat'
	@(x86_64-w64-mingw32-gcc -I _include -Os -fno-jump-tables -c nslookup/nslookup.c -o _bin/nslookup.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/nslookup.x64.o) && echo '[*] nslookup' || echo '[X] nslookup'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c routerprint/routerprint.c -o _bin/routerprint.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/routerprint.x64.o) && echo '[*] routerprint' || echo '[X] routerprint'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c uptime/uptime.c -o _bin/uptime.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/uptime.x64.o) && echo '[*] uptime' || echo '[X] uptime'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c useridletime/useridletime.c -o _bin/useridletime.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/useridletime.x64.o) && echo '[*] useridletime' || echo '[X] useridletime'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c whoami/whoami.c -o _bin/whoami.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/whoami.x64.o) && echo '[*] whoami' || echo '[X] whoami'
	@(python3 ./privcheck/download_vulnerable_driver_list.py)
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -o _bin/vulndrivers.x64.o privcheck/vulnerabledrivers.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/vulndrivers.x64.o) && echo '[*] vulndrivers' || echo '[X] vulndrivers build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -o _bin/alwayselevated.x64.o privcheck/alwaysinstallelevated.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/alwayselevated.x64.o) && echo '[*] alwayselevated' || echo '[X] alwayselevated build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -o _bin/hijackablepath.x64.o privcheck/hijackablepath.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/hijackablepath.x64.o) && echo '[*] hijackablepath' || echo '[X] hijackablepath build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -o _bin/tokenpriv.x64.o privcheck/tokenprivileges.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/tokenpriv.x64.o) && echo '[*] tokenpriv' || echo '[X] tokenpriv build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -o _bin/unattendfiles.x64.o privcheck/unattendfiles.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/unattendfiles.x64.o) && echo '[*] unattendfiles' || echo '[X] unattendfiles build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -o _bin/unquotedsvc.x64.o privcheck/unquotedsvcpath.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/unquotedsvc.x64.o) && echo '[*] unquotedsvc' || echo '[X] unquotedsvc build failed'
	@(x86_64-w64-mingw32-gcc -masm=intel -w -o _bin/winver.x64.o -I ./_include/ -Os -s -c winver/Winver.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/winver.x64.o) && echo '[*] winver' || echo '[X] winver build failed'