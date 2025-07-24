# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="08001109a7d679fe33b04fa51d681bd40b975d8f5cea8c3ef6c0eccb6a7338ce"
    
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