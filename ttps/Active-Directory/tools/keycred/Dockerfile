# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"
    
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