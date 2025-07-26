# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/enum4linux/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
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
        build-base \
        linux-headers \
        samba-client \
        samba-common-tools \
        yaml-dev \
        python3 \
        py3-pip

# https://github.com/DataDog/guarddog (comment out below to skip python package scanning)
RUN \
    python3 -m venv guarddog; \
    . guarddog/bin/activate; \
    pip install --upgrade pip guarddog; \
    mkdir /guarddog-results; \
    # scan packagees
    guarddog pypi scan impacket --output-format=json >> /guarddog-results/impacket.json; \
    guarddog pypi scan ldap3 --output-format=json >> /guarddog-results/ldap3.json; \
    guarddog pypi scan PyYAML --output-format=json >> /guarddog-results/PyYAML.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

WORKDIR /

COPY . .

RUN \
    python3 -m venv enum4linux; \
    . enum4linux/bin/activate; \
    pip install --upgrade pip; \
    pip install -r requirements.txt; \
    apk del --purge --no-network \
        libgcc \
        libstdc++ \
        musl-dev \
        build-base \
        linux-headers; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
