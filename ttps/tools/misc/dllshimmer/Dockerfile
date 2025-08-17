# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
    
FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder
    
RUN \
    apk add --no-cache -U \
        build-base \
        ca-certificates \
        go \
        mingw-w64-gcc \
        mingw-w64-binutils

COPY . .

RUN \
    go build -o dllshimmer; \
    rm -rf /var/cache/apk/*
    
FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache -U \
    bash \
    mingw-w64-gcc \
    mingw-w64-binutils

COPY --from=go-builder /dllshimmer /usr/local/bin/

CMD [ "bash" ]
# dllshimmer -h