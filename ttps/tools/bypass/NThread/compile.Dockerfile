FROM docker.io/debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN \
    apt-get update; \
    apt-get install -y \
        bash \
        make \
        gcc \
        git \
        build-essential \
        cmake \
        g++-mingw-w64-x86-64 \
        gcc-mingw-w64-i686 \
        gcc-mingw-w64-x86-64 \
        binutils-mingw-w64-x86-64 \
        binutils-mingw-w64-i686; \
    mkdir /_bin 2>/dev/null; \
    echo 'creating _bin directory' || echo '_bin directory exists'

COPY . .
WORKDIR _bin

RUN \
    cmake .. \
    -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
    -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
    -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres \
    -DCMAKE_SYSTEM_NAME=Windows-GNU; \
    make; \
    echo '[*] NThread compiled.' || echo '[X] NThread compiled.'

RUN ls -la
CMD [ 'bash' ]

