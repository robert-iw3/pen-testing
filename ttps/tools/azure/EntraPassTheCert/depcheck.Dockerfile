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
    guarddog pypi scan asyauth --output-format=json >> /guarddog-results/asyauth.json; \
    guarddog pypi scan aardwolf --output-format=json >> /guarddog-results/aardwolf.json; \
    guarddog pypi scan termcolor --output-format=json >> /guarddog-results/termcolor.json; \
    guarddog pypi scan xmltodict --output-format=json >> /guarddog-results/xmltodict.json; \
    guarddog pypi scan roadlib --output-format=json >> /guarddog-results/roadlib.json; \
    guarddog pypi scan roadrecon --output-format=json >> /guarddog-results/roadrecon.json; \
    guarddog pypi scan requests --output-format=json >> /guarddog-results/requests.json; \
    guarddog pypi scan impacket --output-format=json >> /guarddog-results/impacket.json; \
    guarddog pypi scan pywinrm --output-format=json >> /guarddog-results/pywinrm.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .