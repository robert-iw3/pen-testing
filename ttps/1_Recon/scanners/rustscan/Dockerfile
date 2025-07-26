# syntax=docker/dockerfile:1
# rustscan: The Modern Port Scanner. Find ports quickly (3 seconds at its fastest). Run scripts through our scripting engine (Python, Lua, Shell supported).
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
    
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
