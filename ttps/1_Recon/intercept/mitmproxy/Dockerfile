# syntax=docker/dockerfile:1
# mitmproxy: A set of tools that provide an interactive, SSL/TLS-capable intercepting proxy for HTTP/1, HTTP/2, and WebSockets.
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
        chromium \
        gosu \
        curl \
        tzdata \
        openssl \
        libssl-dev \
        libffi-dev libxml2-dev libxslt-dev \
        ca-certificates \
        build-essential \
        python3-dev \
        python3-pip \
        pipx

RUN \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh; \
    chmod +x rustup.sh && bash -c "./rustup.sh -y"; \
    rustup-init; \
    rustup update; \
    rustup install stable; \
    rustup toolchain install nightly --component rust-src; \
    cargo install --locked bpf-linker

RUN \
    useradd -mU mitmproxy; \
    mkdir -p /home/mitmproxy/.mitmproxy; \
    chown -R mitmproxy:mitmproxy /home/mitmproxy/.mitmproxy; \
    pipx ensurepath; \
    pipx install mitmproxy; \
    rustup self uninstall; \
    apt-get remove -y libffi-dev libxml2-dev libxslt-dev; \
    apt-get autoremove; \
    rm -rf /root/.cache/*

CMD [ "bash" ]
#VOLUME /home/mitmproxy/.mitmproxy
#COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/
#ENTRYPOINT ["docker-entrypoint.sh"]
#EXPOSE 8080 8081
#CMD ["mitmproxy"]