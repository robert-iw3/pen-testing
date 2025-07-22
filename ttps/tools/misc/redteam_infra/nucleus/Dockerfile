FROM docker.io/node:latest AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

COPY . .

FROM docker.io/node:slim
WORKDIR /app

COPY --from=builder /app ./

RUN \
    apt-get update; \
    apt-get -y install \
        wget \
        curl \
        gnupg \
        software-properties-common \
        netcat-traditional \
        unzip \
        pipx

RUN \
    wget -O- https://apt.releases.hashicorp.com/gpg | \
        gpg --dearmor | \
        tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null; \
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
        https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
        tee /etc/apt/sources.list.d/hashicorp.list; \
    apt-get update; \
    apt-get -y install terraform

RUN \
    ARCH=$(dpkg --print-architecture) ; \
    if [ "$ARCH" = "amd64" ]; then \
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" ; \
        elif [ "$ARCH" = "arm64" ]; then \
        curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"; \
        else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi ; \
    unzip awscliv2.zip ; \
    ./aws/install ; \
    rm -rf aws awscliv2.zip

RUN \
    pipx ensurepath; \
    pipx install --include-deps ansible

RUN \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/$(. /etc/os-release && echo "$VERSION_CODENAME").noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg > /dev/null ; \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/$(. /etc/os-release && echo "$VERSION_CODENAME").tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list > /dev/null ; \
    apt-get update ; \
    apt-get install -y tailscale

CMD ["sh", "/app/entrypoint.sh"]
