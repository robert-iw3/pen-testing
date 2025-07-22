# syntax=docker/dockerfile:1
# bitchat-terminal: A terminal client for BitChat - the decentralized, encrypted mesh network chat protocol that works over Bluetooth LE.
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
        libdbus-1-dev \
        pkg-config

COPY . .

RUN \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh; \
    chmod +x rustup.sh && bash -c "./rustup.sh -y"; \
    rustup-init; \
    rustup update; \
    rustup install stable; \
    rustup toolchain install nightly --component rust-src; \
    cargo install --root /usr/local --path .

RUN \
    apt-get remove -y build-essential; \
    apt-get autoremove -y

CMD [ "bash" ]