FROM docker.io/debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN \
    apt-get update; \
    apt-get install -y \
        bash \
        make \
        gcc \
        build-essential \
        cmake \
        git \
        g++-mingw-w64-x86-64 \
        gcc-mingw-w64-i686 \
        gcc-mingw-w64-x86-64; \
    git clone https://github.com/fortra/nanodump.git

WORKDIR /nanodump

RUN \
    make -f Makefile.mingw; \
    echo '[*] nanodump compiled.' || echo '[X] nanodump compiled.'

RUN ls -la
CMD [ 'sh' ]

