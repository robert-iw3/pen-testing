#!/bin/sh
cd /build
sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
apk update
apk add musl-dev build-base

gcc shell.c -S -o shell.S
as --64 -o shell.o shell.S
ld -shared -nostdlib -z noseparate-code -z max-page-size=0x1000 -o shell.so shell.o
strip --strip-all shell.so
truncate -s 10240 shell.so