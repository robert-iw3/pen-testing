# syntax=docker/dockerfile:1
# sqlmap-ai: An AI-powered wrapper around SQLMap that makes SQL injection testing more accessible and automated.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/sqlmap-ai/bin:/usr/local/bin:/usr/bin:$PATH \
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
    python3 -m venv sqlmap-ai; \
    . sqlmap-ai/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade requests; \
    python3 -m pip install --upgrade python-dotenv; \
    python3 -m pip install --upgrade groq; \
    rm -rf /var/cache/apk/* /root/.cache/*

COPY . .

CMD [ "bash", "-c", "python3 ./run.py --adaptive" ]