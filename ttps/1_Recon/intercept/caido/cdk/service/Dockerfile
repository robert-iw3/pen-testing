#FROM docker.io/almalinux:9.2-minimal as base
FROM quay.io/almalinuxorg/9-minimal@sha256:b394fe1118d30b9659076dd4cf3e1bcbd144a19da5b4656e282ed605a499c4bb as base

RUN \
    microdnf install -y yum-utils; \
    dnf config-manager --set-enabled crb; \
    /usr/bin/crb enable; \
    microdnf install -y epel-release; \
    microdnf update -y; \
    microdnf install -y ca-certificates \
                        clamav \
                        clamav-update \
                        openscap \
                        scap-security-guide \
                        wget \
                        bzip2

FROM base as download

RUN \
    microdnf install -y curl jq; \
    curl -s https://api.caido.io/releases/latest \
    | jq '.links[] | select(.display == "Linux") | .link' \
    | xargs curl -s --output caido.tar.gz; \
    tar -xf caido.tar.gz; \
    rm -f caido.tar.gz

FROM base

LABEL org.opencontainers.image.name='Caido' \
      org.opencontainers.image.description='A lightweight web security auditing toolkit.' \
      org.opencontainers.image.usage='https://docs.caido.io/user_guide' \
      org.opencontainers.image.url='https://caido.io/' \
      org.opencontainers.image.vendor='Caido' \
      org.opencontainers.image.schema-version='0.28.0' \
      MAINTAINER="@rw"

RUN groupadd -g 1007 caido; \
    useradd -u 1007 -r -g caido caido -m

COPY --chown=caido:caido --from=download caido /usr/bin/caido

WORKDIR /home/caido/artifacts

ARG SCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig
ARG SCAP_SNAME=STIG
ARG BENCHMARK=ssg-almalinux9-ds.xml

COPY --chmod=755 el9-container-hardening.sh .

RUN \
    bash -c "./el9-container-hardening.sh"; \
    wget https://security.almalinux.org/oval/org.almalinux.alsa-9.xml; \
    oscap oval eval --report caido-alma9-cve-report.html org.almalinux.alsa-9.xml || :; \
    oscap ds sds-validate /usr/share/xml/scap/ssg/content/${BENCHMARK} \ && echo "ok" || echo "exit code = $? not ok"; \
    oscap xccdf eval --profile ${SCAP_PROFILE} --results caido_alma9-${SCAP_SNAME}-scap-report.xml \
    --report caido_alma9-${SCAP_SNAME}-scap-report.html /usr/share/xml/scap/ssg/content/${BENCHMARK} || :; \           
    freshclam; \
    clamscan -rvi -l clamav_scan.log --exclude-dir="^/sys|^/dev" / || :; \
    chown -R caido:caido /home/caido; \
    grep -Hrn FOUND clamav_scan.log; \   
    microdnf remove -y clamav clamav-update openscap scap-security-guide wget bzip2 yum-utils epel-release dnf-plugins-core; \  
    microdnf clean all; \
    rm -rf /var/cache/dnf /var/cache/yum /tmp/* /var/tmp/*; \
    truncate -s 0 /var/log/*log

USER caido
EXPOSE 8080
ENTRYPOINT [ "caido" ]
CMD [ "--listen", "0.0.0.0:8080" ] 
