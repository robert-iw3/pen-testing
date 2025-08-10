# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/root/.local/bin:/usr/local/bin:/usr/bin:$PATH \
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
        autoconf \
        curl \
        git \
        musl-dev \
        linux-headers \
        python3-dev \
        py3-pip \
        pipx

RUN \
    pipx ensurepath; \
    pipx install git+https://github.com/Mazars-Tech/AD_Miner.git; \
    apk del --purge --no-network \
        libgcc \
        libstdc++ \
        autoconf \
        curl \
        git \
        musl-dev \
        linux-headers \
        py3-pip; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# AD-miner -h