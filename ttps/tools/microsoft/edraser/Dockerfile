# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/edraser/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache \
        bash \
        curl \
        tzdata \
        ca-certificates \
        libgcc \
        libstdc++ \
        build-base \
        musl-dev \
        linux-headers \
        python3-dev \
        py3-pip

# https://github.com/DataDog/guarddog (comment out below to skip python package scanning)
RUN \
    python3 -m venv guarddog; \
    . guarddog/bin/activate; \
    pip install --upgrade pip guarddog; \
    mkdir /guarddog-results; \
    # scan packagees
    guarddog pypi scan impacket --version 0.10.0 --output-format=json >> /guarddog-results/impacket.json; \
    guarddog pypi scan mysql_connector_repackaged --version 0.3.1 --output-format=json >> /guarddog-results/mysql_connector_repackaged.json; \
    guarddog pypi scan psutil --version 5.8.0 --output-format=json >> /guarddog-results/psutil.json; \
    guarddog pypi scan Requests --version 2.32.0 --output-format=json >> /guarddog-results/Requests.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

WORKDIR /

COPY . .

RUN \
    python3 -m venv edraser; \
    . edraser/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install -r requirements.txt; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# python3 EDRaser.py -h