# syntax=docker/dockerfile:1
# OUned: The OUned project, an exploitation tool automating Organizational Units ACLs abuse through gPLink manipulation.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/OUned/bin:/usr/local/bin:/usr/bin:$PATH \
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
    python3 -m venv OUned; \
    . OUned/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade ldap3; \
    python3 -m pip install --upgrade impacket; \
    python3 -m pip install --upgrade dnspython; \
    python3 -m pip install --upgrade typer[all]; \
    rm -rf /var/cache/apk/* /root/.cache/*

COPY . .

CMD [ "bash" ]
