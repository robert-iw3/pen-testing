# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

# usage: Sprayer [-h] [-v] -sp SPRAY_PASSWORD [-oH OUTPUT_HASHES] [-T THREADS] [-P PORT] [-u USERNAME] [-p PASSWORD]
#                [-d DOMAIN] [--hashes [LMHASH]:NTHASH] [--no-pass] [--dc-ip ip address]
#
# add more option here in ARG/ENV

ARG user \
    password \
    domain \
    dc_ip \
    spray_pass

ENV PATH=/pysprayer/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC \
    USER=$user \
    PASSWORD=$password \
    DOMAIN=$domain \
    DC_IP=$dc_ip \
    SPRAY_PASS=$spray_pass

RUN \
    apk add --no-cache \
        bash \
        curl \
        tzdata \
        grep \
        ca-certificates \
        libgcc \
        libstdc++ \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip

COPY . .

RUN \
    python3 -m venv pysprayer; \
    . pysprayer/bin/activate; \
    pip install --upgrade pip impacket sectools; \
    apk del --purge --no-network libgcc libstdc++ musl-dev linux-headers py3-pip; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash", "-c", "./Sprayer.py -u '${USER}' -p '${PASSWORD}' -d '${DOMAIN}' --dc-ip ${DC_IP} -sp '${SPRAY_PASS}'" ]