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
    guarddog pypi scan click --output-format=json >> /guarddog-results/click.json; \
    guarddog pypi scan Flask --output-format=json >> /guarddog-results/Flask.json; \
    guarddog pypi scan Flask-RESTful --output-format=json >> /guarddog-results/Flask-RESTful.json; \
    guarddog pypi scan Flask-WTF --output-format=json >> /guarddog-results/Flask-WTF.json; \
    guarddog pypi scan mysql-connector-python --output-format=json >> /guarddog-results/mysql-connector-python.json; \
    guarddog pypi scan pycryptodome --output-format=json >> /guarddog-results/pycryptodome.json; \
    guarddog pypi scan certifi --output-format=json >> /guarddog-results/certifi.json; \
    guarddog pypi scan chardet --output-format=json >> /guarddog-results/chardet.json; \
    guarddog pypi scan idna --output-format=json >> /guarddog-results/idna.json; \
    guarddog pypi scan requests --output-format=json >> /guarddog-results/requests.json; \
    guarddog pypi scan urllib3 --output-format=json >> /guarddog-results/urllib3.json; \
    guarddog pypi scan turbo_flask --output-format=json >> /guarddog-results/turbo_flask.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .