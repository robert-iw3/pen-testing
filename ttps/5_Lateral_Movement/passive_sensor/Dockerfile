# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:edge" \
    image_hash="20c6c97faaa88f32bbbc45696d259f0c01404a4ec2f1fa4fa8bc5aa5140443ec"
    
FROM ${repo}/${base_image}@sha256:${image_hash} AS base

LABEL \
    org.opencontainers.image.name='Passive Network Mapper' \
    org.opencontainers.image.description='Passively and undetectable gather information about hosts and clients participating in an ethernet segment.' 

FROM base AS go-builder

ENV GOPATH=/go \
    SNYK_API=

RUN \
    apk add --no-cache -t .pnmap-deps \
        ca-certificates \
        go \
        npm; \
    apk add --no-cache -t .av-scan \
        clamav \
        freshclam; \
    mkdir -p ${GOPATH}/src/pnmap

WORKDIR /go/src/pnmap

COPY . .

RUN \
#   npm install -g snyk; \
#   npm install -g snyk-to-html; \
#   snyk config set api=${SNYK_API}; \
#    snyk code test --json | snyk-to-html -o /pnmap-code-review.html; \
#    snyk test --json | snyk-to-html -o /pnmap-deps.html; \
#    snyk monitor; \ 
    export GO111MODULE=on; \
    go mod download; \
    go generate; \
    go build; \
    apk del --no-network --purge .pnmap-deps; \
    #freshclam; \
    #clamscan -rvi -l /clamav_scan.log --exclude-dir="^/sys|^/dev" /; \
    #grep -Hrn FOUND /clamav_scan.log; \ 
    apk del --no-network --purge .av-scan; \
    rm -rf /var/cache/apk/*

FROM base

RUN \
    addgroup -g 65535 pnmap; \
    adduser --shell /sbin/nologin --disabled-password -h /home/pnmap --uid 65535 --ingroup pnmap pnmap
    
COPY --chown=pnmap:pnmap --from=go-builder /go/src/pnmap/pnmap /usr/local/bin
#COPY --chown=pnmap:pnmap --from=go-builder /clamav_scan.log /home/pnmap
#COPY --chown=pnmap:pnmap --from=go-builder /pnmap-code-review.html /home/pnmap
#COPY --chown=pnmap:pnmap --from=go-builder /pnmap-deps.html /home/pnmap

WORKDIR /home/pnmap/
USER pnmap
ARG interface
ENV INTERFACE=$interface
CMD [ "sh", "-c", "pnmap monitor -i $INTERFACE" ]
# sudo podman build --build-arg interface=wlo1 -t pnmap .
#sudo podman run --rm -it --name pnmap \
#   --net=host \
#   --cap-add=net_admin \
#   --cap-add=net_raw \
#   --cap-add=sys_nice \
#   pnmap