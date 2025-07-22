# syntax=docker/dockerfile:1
# rustscan: The Modern Port Scanner. Find ports quickly (3 seconds at its fastest). Run scripts through our scripting engine (Python, Lua, Shell supported).
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="08001109a7d679fe33b04fa51d681bd40b975d8f5cea8c3ef6c0eccb6a7338ce"
    
FROM ${repo}/${base_image}@sha256:${image_hash} AS builder

RUN \
    apk add --no-cache \
        bash \
        ca-certificates \
        nmap \
        nmap-scripts \
        wget \
        git \
        bind-tools \
        libgcc \
        libstdc++ \
        openssl \
        openssl-dev \
        musl-dev \
        cargo \
        rust; \
    update-ca-certificates; \
    git clone https://github.com/bee-san/RustScan.git . ; \
    cargo install rustscan

FROM ${repo}/${base_image}@sha256:${image_hash}

LABEL \
    org.opencontainers.image.name='rustscan' \
    org.opencontainers.image.description='The Modern Port Scanner.'

RUN \
    apk add --no-cache \
        bash \
        ca-certificates \
        nmap \
        nmap-scripts \
        wget \
        bind-tools \
        libgcc \
        libstdc++ \
        openssl; \
    update-ca-certificates
    
COPY --from=builder /root/.cargo/bin/rustscan /usr/local/bin/rustscan
CMD ["bash"]
