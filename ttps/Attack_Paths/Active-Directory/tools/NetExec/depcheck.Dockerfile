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
    guarddog pypi scan aardwolf --output-format=json >> /guarddog-results/aardwolf.json; \
    guarddog pypi scan argcomplete --output-format=json >> /guarddog-results/argcomplete.json; \
    guarddog pypi scan asyauth --output-format=json >> /guarddog-results/asyauth.json; \
    guarddog pypi scan beautifulsoup4 --version 5.0 --output-format=json >> /guarddog-results/beautifulsoup4.json; \
    guarddog pypi scan bloodhound-ce --output-format=json >> /guarddog-results/bloodhound-ce.json; \
    guarddog pypi scan dploot --output-format=json >> /guarddog-results/dploot.json; \
    guarddog pypi scan dsinternals --output-format=json >> /guarddog-results/dsinternals.json; \
    guarddog pypi scan jwt --output-format=json >> /guarddog-results/jwt.json; \
    guarddog pypi scan lsassy --output-format=json >> /guarddog-results/lsassy.json; \
    guarddog pypi scan masky --output-format=json >> /guarddog-results/masky.json; \
    guarddog pypi scan minikerberos --output-format=json >> /guarddog-results/minikerberos.json; \
    guarddog pypi scan neo4j --output-format=json >> /guarddog-results/neo4j.json; \
    guarddog pypi scan paramiko --output-format=json >> /guarddog-results/paramiko.json; \
    guarddog pypi scan pyasn1-modules --output-format=json >> /guarddog-results/pyasn1-modules.json; \
    guarddog pypi scan pylnk3 --output-format=json >> /guarddog-results/pylnk3.json; \
    guarddog pypi scan pypsrp --output-format=json >> /guarddog-results/pypsrp.json; \
    guarddog pypi scan pypykatz --output-format=json >> /guarddog-results/pypykatz.json; \
    guarddog pypi scan python-dateutil --output-format=json >> /guarddog-results/python-dateutil.json; \
    guarddog pypi scan python-libnmap --output-format=json >> /guarddog-results/python-libnmap.json; \
    guarddog pypi scan requests --output-format=json >> /guarddog-results/requests.json; \
    guarddog pypi scan rich --output-format=json >> /guarddog-results/rich.json; \
    guarddog pypi scan sqlalchemy --output-format=json >> /guarddog-results/sqlalchemy.json; \
    guarddog pypi scan termcolor --output-format=json >> /guarddog-results/termcolor.json; \
    guarddog pypi scan terminaltables --output-format=json >> /guarddog-results/terminaltables.json; \
    guarddog pypi scan xmltodict --output-format=json >> /guarddog-results/xmltodict.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .