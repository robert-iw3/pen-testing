# CreateProcess

A small PoC that creates processes in Windows

Modify code injection in process and compile with compile.Dockerfile

```bash
# compile
podman build -t compiler -f compile.Dockerfile

# runtime to retrieve x64 executable
podman run -it --name compiler -d compiler

# see exe
podman exec compiler ls -la dist/

drwxrwxr-x 1 root root  4096 Jun 26 23:36 .
drwxr-xr-x 1 root root  4096 Jun 26 23:36 ..
-rwxr-xr-x 1 root root 62976 Jun 26 23:36 createProcess.x64.exe

# get exe
podman cp compiler:/createprocess/dist .
```