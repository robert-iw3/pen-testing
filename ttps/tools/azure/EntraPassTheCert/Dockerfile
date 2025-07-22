# syntax=docker/dockerfile:1
FROM docker.io/debian:trixie

ENV PATH=/entraptc/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
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
        build-essential \
        python3-dev \
        python3-pip \
        python3-venv

COPY . .

RUN \
    python3 -m venv entraptc; \
    . entraptc/bin/activate; \
    pip install --upgrade pip setuptools; \
    pip install -r requirements.txt; \
    rm -rf /root/.cache/*

CMD [ "bash" ]