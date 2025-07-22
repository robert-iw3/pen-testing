# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="08001109a7d679fe33b04fa51d681bd40b975d8f5cea8c3ef6c0eccb6a7338ce"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/metagoofil/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
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
        grep \
        ca-certificates \
        libgcc \
        libstdc++ \
        proxychains-ng \
        git \
        openssl \
        openssh \
        libxml2 \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip

# https://github.com/DataDog/guarddog (comment out below to skip python package scanning)
RUN \
    python3 -m venv guarddog; \
    . guarddog/bin/activate; \
    pip install --upgrade pip guarddog; \
    mkdir /guarddog-results; \
    # scan packagees
    guarddog pypi scan google --version 3.0.0 --output-format=json >> /guarddog-results/google.json; \
    guarddog pypi scan requests --version 2.32.3 --output-format=json >> /guarddog-results/requests.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

WORKDIR /

COPY . .

RUN \
    python3 -m venv metagoofil; \
    . metagoofil/bin/activate; \
    pip install --upgrade pip setuptools; \
    pip install -r requirements.txt; \
    apk del --purge --no-network \
        libgcc \
        libstdc++ \
        git \
        libxml2 \
        musl-dev \
        linux-headers \
        py3-pip; \
    rm -rf /var/cache/apk/* /root/.cache/*; \
    mv /proxychains.conf /etc/proxychains/proxychains.conf

#CMD [ "bash" ]
ENTRYPOINT [ "bash", "-c", "python3 metagoofil.py -o /data" ]
# python3 metagoofil.py -h
