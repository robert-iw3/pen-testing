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
    guarddog pypi scan pexpect --output-format=json >> /guarddog-results/pexpect.json; \
    guarddog pypi scan pycrypto --output-format=json >> /guarddog-results/pycrypto.json; \
    guarddog pypi scan requests --output-format=json >> /guarddog-results/requests.json; \
    guarddog pypi scan pyopenssl --output-format=json >> /guarddog-results/pyopenssl.json; \
    guarddog pypi scan pefile --output-format=json >> /guarddog-results/pefile.json; \
    guarddog pypi scan impacket --output-format=json >> /guarddog-results/impacket.json; \
    guarddog pypi scan qrcode --output-format=json >> /guarddog-results/qrcode.json; \
    guarddog pypi scan pillow --output-format=json >> /guarddog-results/pillow.json; \
    guarddog pypi scan pymssql --version 3.0 --output-format=json >> /guarddog-results/pymssql.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .