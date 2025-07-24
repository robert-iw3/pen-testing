# syntax=docker/dockerfile:1
FROM docker.io/debian:trixie

ENV PATH=/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
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
        git \
        python3-dev \
        python3-pip \
        python3-venv

# https://github.com/DataDog/guarddog
RUN \
    python3 -m venv guarddog; \
    . guarddog/bin/activate; \
    pip install --upgrade pip guarddog; \
    mkdir /guarddog-results; \
    # scan packagees
    guarddog pypi scan ldap3 --output-format=json >> /guarddog-results/ldap3.json; \
    guarddog pypi scan pyasn1 --output-format=json >> /guarddog-results/pyasn1.json; \
    guarddog pypi scan impacket --output-format=json >> /guarddog-results/impacket.json; \
    guarddog pypi scan rich --output-format=json >> /guarddog-results/rich.json; \
    guarddog pypi scan pycryptodome --output-format=json >> /guarddog-results/pycryptodome.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .