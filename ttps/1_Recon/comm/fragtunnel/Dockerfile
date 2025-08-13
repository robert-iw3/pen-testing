# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/fragtunnel/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache \
        bash \
        curl \
        tzdata \
        ca-certificates \
        proxychains-ng \
        openssl-dev \
        libffi-dev \
        libssl3 \
        openssh \
        libxml2 \
        musl-dev \
        gcc \
        rlwrap \
        linux-headers \
        psutils \
        python3-dev \
        py3-pip \
        privoxy \
        shadow \
        tini \
        socat \
        netcat-openbsd; \
    # privoxy
    mv /etc/privoxy/config.new /etc/privoxy/config ; \
    file='/etc/privoxy/config' ; \
    sed -i 's/listen-address\s*127.0.0.1:8118/listen-address 0.0.0.0:8118/g' $file ; \
    sed -i 's|^\(accept-intercepted-requests\) .*|\1 1|' $file ; \
    sed -i '/^listen/s|127\.0\.0\.1||' $file ; \
    sed -i '/^listen.*::1/s|^|#|' $file ; \
    sed -i 's|^\(logfile\)|#\1|' $file ; \
    sed -i 's|^#\(log-messages\)|\1|' $file ; \
    sed -i 's|^#\(log-highlight-messages\)|\1|' $file ; \
    sed -i '/forward *localhost\//a forward-socks5t / 127.0.0.1:9050 .' $file;\
    sed -i '/^forward-socks5t \//a forward 172.16.*.*/ .' $file ; \
    sed -i '/^forward 172\.16\.\*\.\*\//a forward 172.17.*.*/ .' $file ; \
    sed -i '/^forward 172\.17\.\*\.\*\//a forward 172.18.*.*/ .' $file ; \
    sed -i '/^forward 172\.18\.\*\.\*\//a forward 172.19.*.*/ .' $file ; \
    sed -i '/^forward 172\.19\.\*\.\*\//a forward 172.20.*.*/ .' $file ; \
    sed -i '/^forward 172\.20\.\*\.\*\//a forward 172.21.*.*/ .' $file ; \
    sed -i '/^forward 172\.21\.\*\.\*\//a forward 172.22.*.*/ .' $file ; \
    sed -i '/^forward 172\.22\.\*\.\*\//a forward 172.23.*.*/ .' $file ; \
    sed -i '/^forward 172\.23\.\*\.\*\//a forward 172.24.*.*/ .' $file ; \
    sed -i '/^forward 172\.24\.\*\.\*\//a forward 172.25.*.*/ .' $file ; \
    sed -i '/^forward 172\.25\.\*\.\*\//a forward 172.26.*.*/ .' $file ; \
    sed -i '/^forward 172\.26\.\*\.\*\//a forward 172.27.*.*/ .' $file ; \
    sed -i '/^forward 172\.27\.\*\.\*\//a forward 172.28.*.*/ .' $file ; \
    sed -i '/^forward 172\.28\.\*\.\*\//a forward 172.29.*.*/ .' $file ; \
    sed -i '/^forward 172\.29\.\*\.\*\//a forward 172.30.*.*/ .' $file ; \
    sed -i '/^forward 172\.30\.\*\.\*\//a forward 172.31.*.*/ .' $file ; \
    sed -i '/^forward 172\.31\.\*\.\*\//a forward 10.*.*.*/ .' $file ; \
    sed -i '/^forward 10\.\*\.\*\.\*\//a forward 192.168.*.*/ .' $file ; \
    sed -i '/^forward 192\.168\.\*\.\*\//a forward 127.*.*.*/ .' $file ; \
    sed -i '/^forward 127\.\*\.\*\.\*\//a forward localhost/ .' $file ; \
    mv /etc/privoxy/default.action.new /etc/privoxy/default.action; \
    mv /etc/privoxy/user.action.new /etc/privoxy/user.action; \
    mv /etc/privoxy/default.filter.new /etc/privoxy/default.filter; \
    mv /etc/privoxy/user.filter.new /etc/privoxy/user.filter; \
    mv /etc/privoxy/regression-tests.action.new /etc/privoxy/regression-tests.action; \
    mv /etc/privoxy/trust.new /etc/privoxy/trust; \
    mv /etc/privoxy/match-all.action.new /etc/privoxy/match-all.action; \
    rm -rf /tmp/*

COPY . .

RUN \
    python3 -m venv fragtunnel; \
    . fragtunnel/bin/activate; \
    python3 -m pip install --upgrade pip requests urllib3; \
    rm -rf /var/cache/apk/* /root/.cache/*; \
    apk cache clean

CMD [ "bash" ]