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
    guarddog pypi scan requests --output-format=json >> /guarddog-results/requests.json; \
    guarddog pypi scan PyLaTeX --output-format=json >> /guarddog-results/PyLaTeX.json; \
    guarddog pypi scan python3-nmap --output-format=json >> /guarddog-results/python3-nmap.json; \
    guarddog pypi scan qrcode --output-format=json >> /guarddog-results/qrcode.json; \
    guarddog pypi scan Flask --output-format=json >> /guarddog-results/Flask.json; \
    guarddog pypi scan colorama --output-format=json >> /guarddog-results/colorama.json; \
    guarddog pypi scan Flask_Login --output-format=json >> /guarddog-results/Flask_Login.json; \
    guarddog pypi scan python-nmap --output-format=json >> /guarddog-results/python-nmap.json; \
    guarddog pypi scan python-secrets --version 3.0 --output-format=json >> /guarddog-results/python-secrets.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .