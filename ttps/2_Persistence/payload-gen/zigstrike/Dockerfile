FROM docker.io/debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN \
    apt-get update; \
    apt-get install -y \
        build-essential \
        curl \
        wget \
        libssl-dev \
        zlib1g-dev \
        libffi-dev \
        liblzma-dev \
        python3-dev \
        xz-utils; \
    rm -rf /var/lib/apt/lists/*

RUN \
    curl -fsSL https://www.python.org/ftp/python/3.11.13/Python-3.11.13.tgz -o Python-3.11.13.tgz; \
    tar -xvf Python-3.11.13.tgz; \
    cd Python-3.11.13; \
    ./configure --enable-optimizations; \
    make -j 4; \
    make altinstall; \
    rm -rf /Python-3.11.13 /Python-3.11.13.tgz

RUN \
    curl https://bootstrap.pypa.io/get-pip.py | python3.11 ; \
    python3.11 -m pip install --user setuptools flask Werkzeug

WORKDIR /zigstrike

COPY App /zigstrike/App
COPY src /zigstrike/src
COPY build.zig /zigstrike/build.zig

RUN \
    apt-get update ; \
    ARCH=$(uname -m) ; \
    if [ "$ARCH" = "x86_64" ]; then \
        wget --progress=bar:force https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz ; \
        tar -xf zig-linux-x86_64-0.14.0.tar.xz ; \
        mv zig-linux-x86_64-0.14.0 /usr/local/zig ; \
        rm zig-linux-x86_64-0.14.0.tar.xz; \
    elif [ "$ARCH" = "aarch64" ]; then \
        wget --progress=bar:force https://ziglang.org/download/0.14.0/zig-linux-aarch64-0.14.0.tar.xz ; \
        tar -xf zig-linux-aarch64-0.14.0.tar.xz ; \
        mv zig-linux-aarch64-0.14.0 /usr/local/zig ; \
        rm zig-linux-aarch64-0.14.0.tar.xz; \
    else \
        echo "Unsupported architecture: $ARCH" ; exit 1; \
    fi ; \
    ln -s /usr/local/zig/zig /usr/local/bin/zig; \
    mkdir -p /zigstrike/zig-out/bin

EXPOSE 5002

WORKDIR /zigstrike/App

CMD [ "bash", "-c", "python3.11 app.py" ]