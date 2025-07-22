# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="08001109a7d679fe33b04fa51d681bd40b975d8f5cea8c3ef6c0eccb6a7338ce"
    
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