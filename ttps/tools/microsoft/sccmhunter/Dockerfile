# syntax=docker/dockerfile:1
FROM docker.io/debian:trixie

ENV PATH=/root/.local/bin:/usr/local/bin:/usr/bin:$PATH \
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
        pipx

RUN \
    pipx ensurepath; \
    pipx install git+https://github.com/garrettfoster13/sccmhunter; \
    apt-get remove -y \
        git \
        libssl-dev \
        libffi-dev \
        build-essential \
        python3-pip; \
    apt-get autoremove; \
    rm -rf /root/.cache/*

CMD [ "bash" ]
# sccmhunter.py -h