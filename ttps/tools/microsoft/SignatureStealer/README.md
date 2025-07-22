# Signature Kid

Signature Kid is a header only tool that steals a signature from a file and copy it to whathever file you want.

Beyond Stealing, Signature Kid goes a step further by Windows Internal to trick the system to treat the copied signature as valid.

![image](https://github.com/user-attachments/assets/2121e424-31e3-4855-bbb8-cd305da132f3)

![image](https://github.com/user-attachments/assets/aca2a9dd-80c8-4616-b1c1-48dea5a35acb)

Compile:

```bash
# modify the output name in compiler.Dockerfile
# RUN \
#    x86_64-w64-mingw32-g++ *.cpp -static-libstdc++ -static-libgcc -o sig-grab.exe; \
#    echo '[*] sig stealer compiled.' || echo '[X] sig stealer compiled.'
#
# -o <name of executable>.exe

podman build -t compiler .

podman run -it --name compiler compiler

podman cp compiler:/_bin/<the name you gave for output>.exe .

# blow away
podman system reset -f
```
