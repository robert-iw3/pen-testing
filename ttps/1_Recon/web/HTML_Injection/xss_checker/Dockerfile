# syntax=docker/dockerfile:1
# XSS Injection Check: Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

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