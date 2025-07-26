# syntax=docker/dockerfile:1
# stunner: Stunner is a tool to test and exploit STUN, TURN and TURN over TCP servers.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
    
FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

ENV CGO_ENABLED=0

RUN \
    apk add --no-cache -t .stunner-deps \
        build-base \
        ca-certificates \
        go \
        git

WORKDIR /src

RUN \
    git clone https://github.com/firefart/stunner.git . ; \
    go mod download; \
    go build -a -o stunner -ldflags="-s -w" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src"

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN \
    addgroup -g 65535 stunner; \
    adduser --shell /sbin/nologin --disabled-password -h /home/stunner --uid 65535 --ingroup stunner stunner; \
    apk add --no-cache \
        bash \
        bind-tools \
        ca-certificates

COPY --chown=stunner:stunner --from=go-builder /src/stunner /usr/local/bin

USER stunner
CMD [ "bash" ]
LABEL \
    org.opencontainers.image.name='stunner' \
    org.opencontainers.image.description='Stunner is a tool to test and exploit STUN, TURN and TURN over TCP servers.' \
    org.opencontainers.image.usage='--debug, -d                   enable debug output (default: false) \
                                    --turnserver value, -s value  turn server to connect to in the format host:port \
                                    --tls                         Use TLS/DTLS on connecting to the STUN or TURN server (default: false) \
                                    --protocol value              protocol to use when connecting to the TURN server. Supported values: tcp and udp (default: "udp") \
                                    --timeout value               connect timeout to turn server (default: 1s) \
                                    --username value, -u value    username for the turn server \
                                    --password value, -p value    password for the turn server \
                                    --help, -h                    show help (default: false)'
# see https://github.com/firefart/stunner/blob/main/Readme.md 