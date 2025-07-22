# syntax=docker/dockerfile:1
# NetExec: A network service exploitation tool that helps automate assessing the security of large networks.
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
        sudo \
        coreutils \
        findutils \
        ca-certificates \
        libgcc \
        libstdc++ \
        libc-dev \
        libffi-dev \
        libxml2-dev \
        libxslt-dev \
        autoconf \
        curl \
        git \
        g++ \
        iputils \
        openssl \
        libssl3 \
        musl-dev \
        linux-headers \
        python3-dev \
        py3-pip \
        pipx \
        rust \
        cargo; \
    \
    pipx ensurepath; \
    pipx install git+https://github.com/Pennyw0rth/NetExec; \
    rm -rf /var/cache/apk/* /root/.cache/*

COPY --chmod=755 entrypoint.sh /usr/local/bin

CMD [ "bash" ]
