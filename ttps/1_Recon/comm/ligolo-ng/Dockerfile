# syntax=docker/dockerfile:1
# Ligolo-ng is a simple, lightweight and fast tool that allows pentesters to establish tunnels
# from a reverse TCP/TLS connection using a tun interface (without the need of SOCKS).
ARG repo="docker.io" \
    base_image="alpine:edge" \
    image_hash="20c6c97faaa88f32bbbc45696d259f0c01404a4ec2f1fa4fa8bc5aa5140443ec"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

ENV GOPATH=/usr/local/bin/go

RUN \
    apk add --no-cache -t .build-deps \
        build-base \
        ca-certificates \
        go \
        git; \
    mkdir -p ${GOPATH}/src/github.com/ligolo-ng

WORKDIR ${GOPATH}/src/github.com/ligolo-ng
RUN git clone https://github.com/nicocha30/ligolo-ng.git .

RUN \
    go build -o ${GOPATH}/bin/proxy cmd/proxy/main.go; \
    apk del --no-network --purge .build-deps; \
    rm -rf /var/cache/apk/*; \
    rm -rf ${GOPATH}/src/github.com

FROM ${repo}/${base_image}@sha256:${image_hash}
RUN apk add --no-cache bash curl
COPY --from=go-builder /usr/local/bin/go/bin/ /usr/local/bin
CMD ["bash"]
# proxy -h
# https://docs.ligolo.ng/Quickstart/