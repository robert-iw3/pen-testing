# syntax=docker/dockerfile:1
# XSS Injection Check: Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/cross_injector/bin:/inject_scan/bin:/usr/local/bin:/usr/bin:$PATH \
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
        grep \
        ca-certificates \
        libgcc \
        libstdc++ \
        libxml2 \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip; \
    \
    python3 -m venv cross_injector; \
    . cross_injector/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade selenium; \
    python3 -m pip install --upgrade webdriver_manager; \
    python3 -m pip install --upgrade termcolor; \
    rm -rf /var/cache/apk/* /root/.cache/*

COPY cross_injector/ .

RUN \
    python3 -m venv inject_scan; \
    . inject_scan/bin/activate

COPY inject_scan/ .

CMD [ "python3" ]
# source /cross_injector ; deactivate
# source /inject_scan ; deactivate
# move between venv's