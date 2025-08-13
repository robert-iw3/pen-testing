# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV GOPATH=/usr/local/bin/go \
    PATH=/usr/local/bin/go:/usr/local/bin:/usr/bin:$PATH

RUN \
    apk add --no-cache \
        bash \
        ca-certificates \
        go

COPY . .
WORKDIR /src
RUN go run main.go
CMD [ "bash" ]
# go run main.go -h