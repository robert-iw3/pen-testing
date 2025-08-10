# syntax=docker/dockerfile:1
# GPOddity: The GPOddity project, aiming at automating GPO attack vectors through NTLM relaying (and more).
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/GPOddity/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache \
        bash \
        tzdata \
        coreutils \
        findutils \
        ca-certificates \
        libgcc \
        libstdc++ \
        iputils \
        openssl \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip; \
    \
    python3 -m venv GPOddity; \
    . GPOddity/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade impacket; \
    python3 -m pip install --upgrade typer[all]; \
    rm -rf /var/cache/apk/* /root/.cache/*

COPY . .

CMD [ "bash" ]
