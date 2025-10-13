# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

ENV GOPATH=/usr/local/bin/go

RUN \
    apk add --no-cache -t \
        build-base \
        ca-certificates \
        go; \
    mkdir -p ${GOPATH}/src/; \
    cd ${GOPATH}/src/

COPY . .

RUN \
    export GO111MODULE=on; \
    go install .; \
    # pac support
    # go install -tags pac . ; \
    rm -rf /var/cache/apk/*; \
    rm -rf ${GOPATH}/src/

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN \
    apk add --no-cache \
        bash \
        bind-tools \
        ca-certificates \
        python3 \
        py3-parsing

COPY --from=go-builder /usr/local/bin/go/bin/ /usr/local/bin/
COPY bbs.json .

CMD [ "bash" ]
# bbs -c bbs.json -v -log-file bbs.log