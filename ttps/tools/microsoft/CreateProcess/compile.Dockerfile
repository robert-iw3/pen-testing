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
        g++-mingw-w64-x86-64 \
        gcc-mingw-w64-i686 \
        gcc-mingw-w64-x86-64

WORKDIR /createprocess
COPY . .

RUN \
    make; \
    echo '[*] createprocess compiled.' || echo '[X] createprocess compiled.'; \
    ls -la dist/

CMD [ 'sh' ]

