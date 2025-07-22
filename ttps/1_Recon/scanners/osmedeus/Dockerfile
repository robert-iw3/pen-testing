FROM docker.io/debian:12

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8

RUN \
	set -e; \
	apt-get upgrade -yq; \
	apt-get update -yq; \
	apt-get install -y \
		bash \
		ca-certificates \
        coreutils \
		curl \
		gnupg \
		iptables \
		apt-transport-https \
		software-properties-common \
		wget \
        git \
        unzip \
        sudo \
        jq \
        vim \
        file \
        nmap \
        masscan \
        chromium

ENV PATH "$PATH:/root/osmedeus-base/binaries/"
WORKDIR /root/

RUN \
	curl -fsSL https://raw.githubusercontent.com/osmedeus/osmedeus-base/master/install.sh > osmedeus_install; \
	chmod +x osmedeus_install; \
	./osmedeus_install

EXPOSE 8000
CMD ["/usr/local/bin/osmedeus","server"]
ENTRYPOINT ["osmedeus"]

