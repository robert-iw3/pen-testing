# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="08001109a7d679fe33b04fa51d681bd40b975d8f5cea8c3ef6c0eccb6a7338ce"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/dirsearch/bin:/usr/local/bin:/usr/bin:$PATH \
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
        iputils \
        openssl \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip

RUN \
    python3 -m venv dirsearch; \
    . dirsearch/bin/activate; \
    pip install --upgrade pip setuptools dirsearch; \
    rm -rf /var/cache/apk/* /root/.cache/*; \
    mkdir -p /usr/share/wordlists/

# move your wordlist here, rename to custom.txt and place in same dir as this dockerfile
COPY custom.txt /usr/share/wordlists/
CMD [ "bash" ]
