# syntax=docker/dockerfile:1
# TREVORspray: A modular password sprayer with threading, SSH proxying, loot modules, and more!
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/trevorproxy/bin:/trevorspray/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache \
        bash \
        curl \
        sudo \
        tzdata \
        grep \
        ca-certificates \
        libgcc \
        libstdc++ \
        proxychains-ng \
        git \
        openssl \
        openssh \
        libxml2 \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip; \
    \
    python3 -m venv trevorproxy; \
    . trevorproxy/bin/activate; \
    pip install --upgrade pip; \
    pip install --upgrade git+https://github.com/blacklanternsecurity/trevorproxy; \
    \
    python3 -m venv trevorspray; \
    . trevorspray/bin/activate; \
    pip install --upgrade pip; \
    pip install --upgrade git+https://github.com/blacklanternsecurity/trevorspray; \
    \
    rm -rf /var/cache/apk/* /root/.cache/*; \
    echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains/proxychains.conf

ARG interface
ENV INTERFACE=$interface
CMD [ "sh" ]
