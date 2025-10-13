# syntax=docker/dockerfile:1
# captaincredz: A modular and discreet password-spraying tool.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/captaincredz/bin:/usr/local/bin:/usr/bin:$PATH \
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
        openssl \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip

COPY . .

RUN \
    python3 -m venv captaincredz; \
    . captaincredz/bin/activate; \
    pip install --upgrade pip requests rich; \
    apk del --purge --no-network libgcc libstdc++ musl-dev linux-headers py3-pip; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]