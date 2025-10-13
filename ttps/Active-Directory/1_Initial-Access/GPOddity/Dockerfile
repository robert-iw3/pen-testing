# syntax=docker/dockerfile:1
# GPOddity: The GPOddity project, aiming at automating GPO attack vectors through NTLM relaying (and more).
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

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
