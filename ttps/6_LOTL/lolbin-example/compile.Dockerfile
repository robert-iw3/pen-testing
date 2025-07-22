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
    mkdir /lolbin 2>/dev/null; \
    echo 'creating /lolbin directory' || echo '/lolbin directory exists'

WORKDIR /lolbin
COPY . .

RUN \
    cmake . \
    -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
    -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
    -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres \
    -DCMAKE_SYSTEM_NAME=Windows-GNU \
    -B build64 -A x64; \
    cmake --build build64 --config Release; \
    echo '[*] lolbin compiled.' || echo '[X] lolbin compiled.'

RUN ls -la
CMD [ 'bash' ]