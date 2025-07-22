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
    guarddog pypi scan boto3 --output-format=json >> /guarddog-results/boto3.json; \
    guarddog pypi scan tldextract --output-format=json >> /guarddog-results/tldextract.json; \
    guarddog pypi scan tzlocal --output-format=json >> /guarddog-results/tzlocal.json; \
    guarddog pypi scan bs4 --output-format=json >> /guarddog-results/bs4.json; \
    guarddog pypi scan lxml --output-format=json >> /guarddog-results/lxml.json; \
    guarddog pypi scan datetime --output-format=json >> /guarddog-results/datetime.json; \
    guarddog pypi scan requests_ntlm --output-format=json >> /guarddog-results/requests_ntlm.json; \
    guarddog pypi scan discordwebhook --output-format=json >> /guarddog-results/discordwebhook.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .