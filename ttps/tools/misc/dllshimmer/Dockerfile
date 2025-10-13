# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

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