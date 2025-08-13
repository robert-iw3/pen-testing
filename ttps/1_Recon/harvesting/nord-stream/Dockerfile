# syntax=docker/dockerfile:1
# nord-stream: A tool that allows you extract secrets stored inside CI/CD environments by deploying _malicious_ pipelines.
# https://github.com/synacktiv/nord-stream
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/nord-stream/bin:/usr/local/bin:/usr/bin:$PATH \
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
        git \
        libgcc \
        libstdc++ \
        openssl \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip

RUN git clone https://github.com/synacktiv/nord-stream.git

WORKDIR /nord-stream

RUN \
    python3 -m venv nord-stream; \
    . nord-stream/bin/activate; \
    pip install --upgrade pip; \
    pip install -r requirements.txt; \
    mv nord-stream/* . ; \
    apk del --purge --no-network \
        git \
        libgcc \
        libstdc++ \
        musl-dev \
        linux-headers \
        py3-pip; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# python3 nord-stream.py -h