# syntax=docker/dockerfile:1
FROM docker.io/debian:trixie

ENV PATH=/root/.local/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
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
        git \
        libssl-dev \
        libffi-dev \
        build-essential \
        python3-dev \
        python3-pip \
        python3-venv \
        pipx \
        python3-netifaces

# https://github.com/DataDog/guarddog (comment out below to skip python package scanning)
RUN \
    python3 -m venv guarddog; \
    . guarddog/bin/activate; \
    pip install --upgrade pip guarddog; \
    mkdir /guarddog-results; \
    # scan packagees
    guarddog pypi scan scapy --output-format=json >> /guarddog-results/scapy.json; \
    guarddog pypi scan termcolor --output-format=json >> /guarddog-results/termcolor.json; \
    guarddog pypi scan netifaces --output-format=json >> /guarddog-results/netifaces.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

RUN \
    pipx ensurepath; \
    pipx install git+https://github.com/AonCyberLabs/DNSForge; \
    apt-get remove -y git libssl-dev libffi-dev build-essential python3-venv; \
    apt-get autoremove -y; \
    rm -rf /root/.cache/*

CMD [ "bash" ]