# syntax=docker/dockerfile:1
# TREVORproxy: A SOCKS proxy written in Python that randomizes your source IP address.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

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
