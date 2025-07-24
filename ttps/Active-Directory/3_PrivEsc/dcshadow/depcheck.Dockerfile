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
    guarddog pypi scan setuptools --version 65.5.1 --output-format=json >> /guarddog-results/setuptools.json; \
    guarddog pypi scan six --version 1.16.0 --output-format=json >> /guarddog-results/six.json; \
    guarddog pypi scan charset_normalizer --output-format=json >> /guarddog-results/charset_normalizer.json; \
    guarddog pypi scan pyasn1 --output-format=json >> /guarddog-results/pyasn1.json; \
    guarddog pypi scan pycryptodomex --output-format=json >> /guarddog-results/pycryptodomex.json; \
    guarddog pypi scan pyOpenSSL --output-format=json >> /guarddog-results/pyOpenSSL.json; \
    guarddog pypi scan ldap3 --output-format=json >> /guarddog-results/ldap3.json; \
    guarddog pypi scan ldapdomaindump --output-format=json >> /guarddog-results/ldapdomaindump.json; \
    guarddog pypi scan flask --output-format=json >> /guarddog-results/flask.json; \
    guarddog pypi scan pycryptodome --output-format=json >> /guarddog-results/pycryptodome.json; \
    guarddog pypi scan dsinternals --version 1.2.4 --output-format=json >> /guarddog-results/dsinternals.json; \
    guarddog pypi scan impacket --output-format=json >> /guarddog-results/impacket.json; \
    guarddog pypi scan hexdump --version 3.3 --output-format=json >> /guarddog-results/hexdump.json; \
    guarddog pypi scan R2Log --version 1.0.1 --output-format=json >> /guarddog-results/R2Log.json; \
    guarddog pypi scan dnspython --version 2.4.2 --output-format=json >> /guarddog-results/dnspython.json; \
    guarddog pypi scan cryptography --version 41.0.7 --output-format=json >> /guarddog-results/cryptography.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

CMD [ "bash" ]
# podman cp depcheck:/guarddog-results .