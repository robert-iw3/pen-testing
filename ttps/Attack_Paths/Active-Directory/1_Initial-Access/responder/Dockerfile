# syntax=docker/dockerfile:1
FROM docker.io/debian:trixie

ENV PATH=/responder/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apt-get update && apt-get install -y \
        bash \
        tzdata \
        ca-certificates \
        libssl-dev \
        libffi-dev \
        build-essential \
        samba \
        python3-dev \
        python3-pip \
        python3-venv \
        python3-netifaces

# https://github.com/DataDog/guarddog (comment out below to skip python package scanning)
RUN \
    python3 -m venv guarddog; \
    . guarddog/bin/activate; \
    pip install --upgrade pip guarddog; \
    mkdir /guarddog-results; \
    # scan packagees
    guarddog pypi scan aioquic --output-format=json >> /guarddog-results/aioquic.json; \
    guarddog pypi scan netifaces --output-format=json >> /guarddog-results/netifaces.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

WORKDIR /

COPY . .

RUN \
    python3 -m venv responder; \
    . responder/bin/activate; \
    pip install --upgrade pip setuptools; \
    pip install -r requirements.txt; \
    rm -rf /root/.cache/*

ARG interface
ENV INTERFACE=$interface
# ports to listen on
EXPOSE 137/udp 138/udp 53/udp 389/udp 389/tcp 1433/tcp 1434/udp 80/tcp 135/tcp 139/tcp 445/tcp 21/tcp 3141/tcp 25/tcp 110/tcp 587/tcp 3128/tcp 5355/udp 5353/udp
CMD [ "bash" ]
# python3 Responder.py -h
