# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

RUN \
    apk add --no-cache \
        build-base \
        ca-certificates \
        go

COPY . .

RUN \
    # Build the TURN credentials utility
    go build -o turnt-credentials ./cmd/credentials; \
    # Build the controller (SOCKS proxy client/controller)
    go build -o turnt-controller ./cmd/controller; \
    # Build the relay (TURN-facing relay side)
    go build -o turnt-relay ./cmd/relay; \
    # Build the admin console utility
    go build -o turnt-admin ./cmd/admin; \
    rm -rf /var/cache/apk/*

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache bash

WORKDIR /bins

COPY --from=go-builder /turnt-credentials .
COPY --from=go-builder /turnt-controller .
COPY --from=go-builder /turnt-relay .
COPY --from=go-builder /turnt-admin .

CMD [ "bash" ]