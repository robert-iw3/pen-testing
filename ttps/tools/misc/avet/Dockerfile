FROM docker.io/debian:12

ARG DEBIAN_FRONTEND=noninteractive

RUN \
	dpkg --add-architecture i386 ; \
	apt-get update; \
	apt-get install -y \
		bash \
		wget \
		curl \
		git \
		unzip \
		jq \
		apt-utils \
		gnupg2 \
		vim \
		nano \
		gedit \
		wine \
		wine32 \
		python \
		python3 \
		mingw-w64; \
	rm -rf /var/lib/apt/lists/*

RUN \
	echo 'deb http://apt.metasploit.com/ buster main' > /etc/apt/sources.list.d/metasploit-framework.list; \
	wget -O - http://apt.metasploit.com/metasploit-framework.gpg.key | apt-key add - ; \
	apt-get update; \
	apt-get install -y metasploit-framework; \
	rm -rf /var/lib/apt/lists/*

WORKDIR /tools/avet
COPY . .

WORKDIR /tools/pe_to_shellcode
RUN curl -s https://api.github.com/repos/hasherezade/pe_to_shellcode/releases/latest \
		| jq -r '.assets[].browser_download_url' \
		| grep 'pe2shc' \
		| wget -i -

WORKDIR /tools/mimikatz
RUN curl -s https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest \
		| jq -r '.assets[].browser_download_url' \
		| grep .'zip' \
		| wget -i - ; \
	unzip mimikatz_trunk.zip; \
	cp x64/mimikatz.exe /tools/avet/input

WORKDIR /tools
RUN git clone https://github.com/Mr-Un1k0d3r/DKMC.git

RUN winecfg

WORKDIR /tools/avet
CMD [ 'bash' ]