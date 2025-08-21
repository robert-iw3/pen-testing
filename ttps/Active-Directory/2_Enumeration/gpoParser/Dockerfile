# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/root/.local/bin:/usr/local/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache -U \
        bash \
        tzdata \
        ca-certificates \
        build-base \
        krb5-dev \
        openldap-dev \
        libsasl \
        git \
        python3-dev \
        pipx

RUN \
    pipx ensurepath ; \
    pipx install git+https://github.com/synacktiv/gpoParser; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# gpoParser -h