# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/gpobackdoor/bin:/usr/local/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache -U \
        bash \
        tzdata \
        ca-certificates \
        build-base \
        openldap-dev \
        samba-dev \
        krb5-dev \
        python3-dev \
        py3-pip

COPY . .

RUN \
    python3 -m venv gpobackdoor; \
    . gpobackdoor/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install -r requirements.txt; \
    \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# python3 gpb.py -h
