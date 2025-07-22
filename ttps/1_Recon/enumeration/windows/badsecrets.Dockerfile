# syntax=docker/dockerfile:1
# badsecrets: A pure python library for identifying the use of known or very weak cryptographic secrets across a variety of platforms.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="08001109a7d679fe33b04fa51d681bd40b975d8f5cea8c3ef6c0eccb6a7338ce"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/badsecrets/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache \
        bash \
        tzdata \
        ca-certificates \
        libgcc \
        libstdc++ \
        libc-dev \
        libffi-dev \
        libxml2-dev \
        libxslt-dev \
        g++ \
        iputils \
        openssl \
        libssl3 \
        musl-dev \
        build-base \
        linux-headers \
        python3-dev \
        py3-pip; \
    \
    python3 -m venv badsecrets; \
    . badsecrets/bin/activate; \
    pip install --upgrade pip setuptools; \
    pip install --upgrade badsecrets; \
    \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# badsecrets -h
# https://github.com/blacklanternsecurity/badsecrets/tree/main