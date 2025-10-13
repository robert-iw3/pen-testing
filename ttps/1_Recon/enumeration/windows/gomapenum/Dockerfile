# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

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