# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/pygpoabuse/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
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
        py3-pip

# https://github.com/DataDog/guarddog (comment out below to skip python package scanning)
RUN \
    python3 -m venv guarddog; \
    . guarddog/bin/activate; \
    pip install --upgrade pip guarddog; \
    mkdir /guarddog-results; \
    # scan packagees
    guarddog pypi scan msldap --output-format=json >> /guarddog-results/msldap.json; \
    guarddog pypi scan impacket --output-format=json >> /guarddog-results/impacket.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

WORKDIR /

COPY . .

RUN \
    python3 -m venv pygpoabuse; \
    . pygpoabuse/bin/activate; \
    pip install --upgrade pip; \
    pip install -r requirements.txt; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# python3 pygpoabuse.py -h