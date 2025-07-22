# syntax=docker/dockerfile:1
# rustpacker: Converts raw shellcode into Windows executables or DLLs using various injection techniques and evasion methods.
FROM docker.io/debian:trixie

ENV PATH=/root/.local/bin:/root/.cargo/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apt-get update; \
    apt-get install -y \
        bash \
        curl \
        tzdata \
        ca-certificates \
        build-essential \
        libssl-dev \
        librust-openssl-dev \
        musl-tools \
        mingw-w64 \
        cmake \
        libxml2-dev \
        g++-mingw-w64-x86-64

COPY . .

RUN \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh; \
    chmod +x rustup.sh && bash -c "./rustup.sh -y"; \
    rustup-init; \
    rustup update; \
    rustup install stable; \
    rustup toolchain install nightly --component rust-src; \
    rustup target add x86_64-pc-windows-gnu; \
    cargo install --root /usr/local --path .

WORKDIR /usr/src/RustPacker/shared
COPY shared/ .

#CMD ["RustPacker"]
CMD [ "bash" ]