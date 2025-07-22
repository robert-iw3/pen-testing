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
    guarddog pypi scan typer[all] --output-format=json >> /guarddog-results/typer[all].json; \
    guarddog pypi scan bs4 --output-format=json >> /guarddog-results/bs4.json; \
    guarddog pypi scan cryptography --output-format=json >> /guarddog-results/cryptography.json; \
    guarddog pypi scan requests_ntlm --output-format=json >> /guarddog-results/requests_ntlm.json; \
    guarddog pypi scan requests_toolbelt --output-format=json >> /guarddog-results/requests_toolbelt.json; \
    guarddog pypi scan pyasn1_modules --output-format=json >> /guarddog-results/pyasn1_modules.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .