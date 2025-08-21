# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
    
FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder
    
RUN \
    apk add --no-cache -U \
        bash \
        tzdata \
        ca-certificates \
        build-base \
        krb5-dev \
        openldap-dev \
        go

COPY . .

RUN \
    go build ./cmd/keycred; \
    go build ./cmd/pfxtool; \
    mv keycred pfxtool /usr/local/bin/; \
    rm -rf /var/cache/apk/*
    
CMD [ "bash" ]
# keycred -h
# pfxtool -h