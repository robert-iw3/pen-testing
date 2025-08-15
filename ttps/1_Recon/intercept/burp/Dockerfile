FROM docker.io/openjdk:25-slim@sha256:28af71b23261d822b8681b3a9d9da5748dc386881eda01354f736e3dd64d0fbd

ARG PORTSWIGGER_EMAIL_ADDRESS
ARG PORTSWIGGER_PASSWORD

ENV BURP_SUITE_PRO_VERSION="2025.7.3"
ENV BURP_SUITE_PRO_CHECKSUM="2a89a404db0b9b446edafbb9e76a40056a20025a137fae6415a19d7b53c4092a"
ENV HOME /home/burp

ENV JAVA_OPTS "-Dawt.useSystemAAFontSettings=gasp "\
  "-Dswing.aatext=true "\
  "-Dsun.java2d.xrender=true" \
  "-XX:+UnlockExperimentalVMOptions "\
  "-XX:+UseCGroupMemoryLimitForHeap "\
  "-XshowSettings:vm"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8

RUN \
    apt-get update -y; \
    apt-get install -y \
        curl \
    	openssl \
       	ca-certificates \
  		fontconfig \
     	libxext6 \
		libxrender1 \
   		libxtst6; \
    addgroup --system burp; \
    adduser --system --ingroup burp burp

COPY --chmod=755 download.sh entrypoint.sh ${HOME}

RUN \
    bash -c "/home/burp/download.sh"; \
    mv "$HOME/burpsuite_pro_v$BURP_SUITE_PRO_VERSION.jar" /home/burp/burpsuite_pro.jar; \
    mkdir -p .java/.userPrefs

RUN \
    apt-get install -y clamav; \
    freshclam; \
    clamscan -rvi -l ${HOME}/clamav_scan.log --exclude-dir="^/sys|^/dev" /; \
    chown burp:burp ${HOME}/clamav_scan.log; \
    grep -Hrn " FOUND" ${HOME}/clamav_scan.log; \
    apt-get remove -y clamav; \
    apt-get autoremove -y; \
    apt-get clean -y; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*; \
    truncate -s 0 /var/log/*log

USER burp
WORKDIR $HOME
# Burp Proxy
EXPOSE 8080
# Burp REST API
EXPOSE 1337
# Set configurations
ADD config config
ENTRYPOINT [ "/home/burp/entrypoint.sh", "/home/burp/burpsuite_pro.jar" ]
