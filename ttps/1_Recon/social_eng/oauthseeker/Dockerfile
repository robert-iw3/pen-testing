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
    go build -o oauthseeker ./cmd/oauthseeker/; \
    rm -rf /var/cache/apk/*
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH="/opt/venv/bin:/usr/bin:/bin:/sbin:/usr/sbin:$PATH"
# azure creds
ARG USER=
ARG PASS=
ARG APP_ID=
ARG TENANT_ID=

#COPY some_azure_cert.pem .

RUN apk add --no-cache --update \
        bash \
        curl \
        jq \
        python3 \
        py3-pip \
        gcc \
        musl-dev \
        python3-dev \
        libffi-dev \
        openssl-dev \
        cargo \
        make; \
    python3 -m venv /opt/venv; \
    . /opt/venv/bin/activate; \
    pip install --upgrade pip; \
    pip install --no-cache-dir azure-cli; \
    deactivate; \
    az login --username ${USER} --password ${PASS}; \
    # az login --service-principal --username ${APP_ID} --certificate some_azure_cert.pem --tenant ${TENANT_ID}; \
    export JWT=$(az account get-access-token --resource https://graph.microsoft.com | jq -r .accessToken); \
    \
    apk del --purge --no-network \
        gcc \
        musl-dev \
        python3-dev \
        libffi-dev \
        openssl-dev \
        cargo \
        make; \
    rm -rf /var/cache/apk/*

COPY --from=go-builder /oauthseeker /usr/local/bin/
EXPOSE 8080
CMD [ "bash" ]