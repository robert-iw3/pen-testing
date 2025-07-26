# syntax=docker/dockerfile:1
# rustpotato: A privilege escalation tool that abuses DCOM and RPC to leverage SeImpersonatePrivilege 
# and gain NT AUTHORITY\SYSTEM privileges on Windows systems.
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
        pkg-config \
        g++-mingw-w64-x86-64

COPY . .

RUN \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh; \
    chmod +x rustup.sh && bash -c "./rustup.sh -y"; \
    rustup-init; \
    rustup update; \
    rustup install stable; \
    rustup toolchain install nightly --component rust-src; \
    rustup toolchain install stable-gnu; \
    rustup target add x86_64-pc-windows-gnu; \
    cargo build --target x86_64-pc-windows-gnu --release --features verbose

RUN \
    apt-get remove -y build-essential g++-mingw-w64-x86-64; \
    apt-get autoremove -y

CMD [ "bash" ]