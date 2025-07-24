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
    guarddog pypi scan beautifulsoup4 --output-format=json >> /guarddog-results/beautifulsoup4.json; \
    guarddog pypi scan colorama --output-format=json >> /guarddog-results/colorama.json; \
    guarddog pypi scan clint --output-format=json >> /guarddog-results/clint.json; \
    guarddog pypi scan tabulate --output-format=json >> /guarddog-results/tabulate.json; \
    guarddog pypi scan Levenshtein --output-format=json >> /guarddog-results/Levenshtein.json; \
    guarddog pypi scan neo4j --version 5.0.0 --output-format=json >> /guarddog-results/neo4j.json; \
    guarddog pypi scan impacket --output-format=json >> /guarddog-results/impacket.json; \
    guarddog pypi scan urllib3 --version 2.0 --output-format=json >> /guarddog-results/urllib3.json; \
    guarddog pypi scan numpy --output-format=json >> /guarddog-results/numpy.json; \
    guarddog pypi scan ansi2image --output-format=json >> /guarddog-results/ansi2image.json; \
    guarddog pypi scan aioconsole --output-format=json >> /guarddog-results/aioconsole.json; \
    guarddog pypi scan minikerberos --output-format=json >> /guarddog-results/minikerberos.json; \
    guarddog pypi scan pypsrp --output-format=json >> /guarddog-results/pypsrp.json; \
    guarddog pypi scan xmltodict --output-format=json >> /guarddog-results/xmltodict.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .