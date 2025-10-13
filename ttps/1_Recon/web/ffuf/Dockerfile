# syntax=docker/dockerfile:1
# ffuf: A fast web fuzzer written in Go.
# https://github.com/ffuf/ffuf
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

ENV GOPATH=/usr/local/bin/go

RUN \
    apk add --no-cache -t .ffuf-deps \
        build-base \
        ca-certificates \
        go \
        git; \
    go install github.com/ffuf/ffuf/v2@latest; \
    apk del --no-network --purge .ffuf-deps; \
    rm -rf /var/cache/apk/*

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN \
    addgroup -g 65535 ffuf; \
    adduser --shell /sbin/nologin --disabled-password -h /home/ffuf --uid 65535 --ingroup ffuf ffuf; \
    apk add --no-cache \
        bash \
        bind-tools \
        ca-certificates \
        chromium

COPY --chown=ffuf:ffuf --from=go-builder /usr/local/bin/go/bin/ffuf /usr/local/bin/
COPY wordlists/ /home/ffuf

WORKDIR /home/ffuf
USER ffuf
CMD [ "bash" ]
# ffuf -h
