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
    guarddog pypi scan ansible-core --version 2.12.0 --output-format=json >> /guarddog-results/ansible-core.json; \
    guarddog pypi scan docker --version 5.0.3 --output-format=json >> /guarddog-results/docker.json; \
    guarddog pypi scan docker-compose --version 1.29.2 --output-format=json >> /guarddog-results/docker-compose.json; \
    guarddog pypi scan dockerpty --version 0.4.1 --output-format=json >> /guarddog-results/dockerpty.json; \
    guarddog pypi scan requests --version 2.25.1 --output-format=json >> /guarddog-results/requests.json; \
    guarddog pypi scan urllib3 --version 1.26.5 --output-format=json >> /guarddog-results/urllib3.json; \
    guarddog pypi scan PyYaml --version 5.3.1 --output-format=json >> /guarddog-results/PyYaml.json; \
    guarddog pypi scan colorama --output-format=json >> /guarddog-results/colorama.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .