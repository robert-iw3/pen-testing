# syntax=docker/dockerfile:1
# TREVORproxy: A SOCKS proxy written in Python that randomizes your source IP address.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/trevorproxy/bin:/usr/local/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin:$PATH \
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
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade git+https://github.com/blacklanternsecurity/trevorproxy; \
    \
    rm -rf /var/cache/apk/* /root/.cache/*

ADD proxychains.conf /etc/proxychains/proxychains.conf

ARG interface
ENV INTERFACE=$interface
CMD [ "bash" ]
