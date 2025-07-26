# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/socialfish/socialfish/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
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
        git \
        coreutils \
        grep \
        ca-certificates \
        libgcc \
        libstdc++ \
        py3-psutil \
        py3-requests \
        py3-nmap \
        py3-qrcode \
        py3-flask \
        py3-colorama \
        py3-flask-login \
        py3-secretstorage \
        py3-jupyter-packaging \
        gcc \
        ethtool \
        nmap \
        musl-dev \
        linux-headers \
        python3 \
        python3-dev \
        py3-pip

WORKDIR /socialfish
RUN git clone https://github.com/UndeadSec/SocialFish.git .

RUN \
    python3 -m venv socialfish; \
    . socialfish/bin/activate; \
    pip install --upgrade pip; \
    pip install -r requirements.txt; \
    rm -rf /var/cache/apk/* /root/.cache/*  

EXPOSE 5000/tcp
CMD [ "bash", "-c", "python3 ./SocialFish.py user password" ]
# Username is: user
# Password is: password
# https://github.com/UndeadSec/SocialFish/wiki/Using-SocialFish



