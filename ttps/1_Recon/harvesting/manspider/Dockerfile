# syntax=docker/dockerfile:1
# https://github.com/blacklanternsecurity/MANSPIDER
ARG repo="docker.io" \
    base_image="python:3.10-slim-bookworm" \
    image_hash="fd939bec23d8e9a1274d70e24db96bceed53e56612f828098f5505086a64f523"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/root/.cargo/bin:/root/.local/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apt-get update && apt-get upgrade -y; \
    \
    apt-get install -y \
        bash \
        curl \
        build-essential \
        krb5-user \
        tesseract-ocr \
        libmagic-dev \
        antiword \
        cargo \
        git \
        rustc \
        openssl \
        pipx

RUN \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh; \
    chmod +x rustup.sh && bash -c "./rustup.sh -y"; \
    rustup-init; \
    rustup update

RUN \
    pipx ensurepath ; \
    pipx install git+https://github.com/blacklanternsecurity/MANSPIDER; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# manspider -h