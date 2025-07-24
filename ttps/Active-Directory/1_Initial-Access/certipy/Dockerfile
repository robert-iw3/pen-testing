# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="08001109a7d679fe33b04fa51d681bd40b975d8f5cea8c3ef6c0eccb6a7338ce"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/certipy/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache \
        bash \
        curl \
        tzdata \
        coreutils \
        git \
        ca-certificates \
        libgcc \
        libstdc++ \
        git \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip; \
    \
    python3 -m venv certipy; \
    . certipy/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade certipy-ad; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# certipy -h
# https://github.com/ly4k/Certipy/wiki/05-%E2%80%90-Usage