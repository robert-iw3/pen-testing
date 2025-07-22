# syntax=docker/dockerfile:1
FROM docker.io/debian:trixie

ENV PATH=/matrix/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
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
        libpcap-dev \
        build-essential \
        python3-dev \
        python3-pip \
        python3-venv

# https://github.com/DataDog/guarddog (comment out below to skip python package scanning)
RUN \
    python3 -m venv guarddog; \
    . guarddog/bin/activate; \
    pip install --upgrade pip guarddog; \
    mkdir /guarddog-results; \
    # scan packagees
    guarddog pypi scan pymodbus --output-format=json >> /guarddog-results/pymodbus.json; \
    guarddog pypi scan scapy --output-format=json >> /guarddog-results/scapy.json; \
    guarddog pypi scan tabulate --output-format=json >> /guarddog-results/tabulate.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

WORKDIR /

COPY . .

RUN \
    python3 -m venv matrix; \
    . matrix/bin/activate; \
    pip install --upgrade pip setuptools; \
    pip install -r requirements.txt; \
    apt-get remove -y build-essential python3-pip python3-venv; \
    apt-get autoremove; \
    rm -rf /root/.cache/*

ARG interface
ENV INTERFACE=$interface
CMD [ "bash" ]
# python3 matrix.py -h
