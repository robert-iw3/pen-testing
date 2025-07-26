# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/pygpoabuse/bin:/usr/local/bin:/usr/bin:$PATH \
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
        musl-dev \
        linux-headers \
        python3 \
        py3-pip; \
    \
    python3 -m venv pygpoabuse; \
    . pygpoabuse/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade impacket; \
    python3 -m pip install --upgrade sectools; \
    python3 -m pip install --upgrade msldap; \
    rm -rf /var/cache/apk/* /root/.cache/*

COPY . .

CMD [ "python3" ]