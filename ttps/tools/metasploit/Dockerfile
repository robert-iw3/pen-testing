# syntax=docker/dockerfile:1
# msf in alpine (not as bad as arch)
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/usr/share/metasploit-framework:/usr/local/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add -U --no-cache \
        build-base \
        ruby \
        ruby-bigdecimal \
        ruby-bundler \
        ruby-webrick \
        ruby-dev \
        libffi-dev\
        openssl-dev \
        readline-dev \
        sqlite-dev \
        postgresql-dev \
        libpcap-dev \
        libxml2-dev \
        libxslt-dev \
        yaml-dev \
        zlib-dev \
        ncurses-dev \
        autoconf \
        bison \
        subversion \
        git \
        sqlite \
        nmap \
        libxslt \
        postgresql \
        ncurses

RUN \
    addgroup -g 1001 tor; \
    adduser --shell /sbin/nologin --disabled-password -h /home/tor --uid 1001 --ingroup tor tor; \
    # add extra packages here, using msf for just exploitation purposes here.
    apk add --no-cache \
        bash \
        curl \
        python3 \
        py3-pip \
        proxychains-ng \
        privoxy \
        tini \
        tmux \
        go \
        openssl \
        hydra \
        postgresql \
        tor \
        torsocks \
        socat \
        vim \
        netcat-openbsd \
        nmap

RUN \
    cd /usr/share ; \
    git clone https://github.com/rapid7/metasploit-framework.git ; \
    cd /usr/share/metasploit-framework ; \
    /usr/bin/bundle update --bundler ; \
    /usr/bin/bundle install

RUN \
    cd / ; \
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
    echo 'AutomapHostsOnResolve 1' >>/etc/tor/torrc ; \
    echo 'AutomapHostsSuffixes .exit,.onion' >>/etc/tor/torrc ; \
    echo 'ControlPort 9051' >>/etc/tor/torrc ; \
    echo 'ControlSocket /etc/tor/run/control' >>/etc/tor/torrc ; \
    echo 'ControlSocketsGroupWritable 1' >>/etc/tor/torrc ; \
    echo 'CookieAuthentication 1' >>/etc/tor/torrc ; \
    echo 'CookieAuthFile /etc/tor/run/control.authcookie' >>/etc/tor/torrc ; \
    echo 'CookieAuthFileGroupReadable 1' >>/etc/tor/torrc ; \
    echo 'DNSPort 5353' >>/etc/tor/torrc ; \
    echo 'DataDirectory /var/lib/tor' >>/etc/tor/torrc ; \
    echo 'ExitPolicy reject *:*' >>/etc/tor/torrc ; \
    echo 'Log notice stderr' >>/etc/tor/torrc ; \
    echo 'RunAsDaemon 0' >>/etc/tor/torrc ; \
    echo 'SocksPort 0.0.0.0:9050 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr' >>/etc/tor/torrc ; \
    echo 'TransPort 0.0.0.0:9040 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr' >>/etc/tor/torrc ; \
    echo 'HardwareAccel 1' >>/etc/tor/torrc ; \
    echo 'TestSocks 1' >>/etc/tor/torrc ; \
    echo 'AllowNonRFC953Hostnames 0' >>/etc/tor/torrc ; \
    echo 'WarnPlaintextPorts 23,109,110,143,80' >>/etc/tor/torrc ; \
    echo 'ClientRejectInternalAddresses 1' >>/etc/tor/torrc ; \
    echo 'NewCircuitPeriod 40' >>/etc/tor/torrc ; \
    echo 'MaxCircuitDirtiness 600' >>/etc/tor/torrc ; \
    echo 'MaxClientCircuitsPending 48' >>/etc/tor/torrc ; \
    echo 'UseEntryGuards 1' >>/etc/tor/torrc ; \
    echo 'EnforceDistinctSubnets 1' >>/etc/tor/torrc ; \
    echo 'User tor' >>/etc/tor/torrc ; \
    echo 'VirtualAddrNetworkIPv4 10.192.0.0/10' >>/etc/tor/torrc ; \
    echo 'HiddenServiceDir /var/lib/tor/hidden_service/' >>/etc/tor/torrc ; \
    echo 'HiddenServicePort 4444 127.0.0.1:4444' >>/etc/tor/torrc ; \
    mkdir -p /etc/tor/run ; \
    chown -Rh tor /var/lib/tor /etc/tor/run ; \
    chmod 0750 /etc/tor/run ; \
    rm -rf /tmp/*

COPY --chmod=755 ./custom /custom
COPY proxychains.conf tmux.conf /

RUN \
    apk del --purge --no-network \
        build-base \
        ruby-dev \
        libffi-dev\
        openssl-dev \
        readline-dev \
        sqlite-dev \
        postgresql-dev \
        libpcap-dev \
        libxml2-dev \
        libxslt-dev \
        yaml-dev \
        zlib-dev \
        ncurses-dev \
        bison \
        autoconf; \
    cp tmux.conf /root/.tmux.conf ; \
    rm -rf /var/cache/apk/* /root/.cache/*; \
    apk cache clean; \
    mv /proxychains.conf /etc/proxychains/proxychains.conf

COPY --chmod=755 torproxy.sh init.sh /usr/bin

EXPOSE 8118 9050 9051

HEALTHCHECK --interval=60s --timeout=15s --start-period=20s \
            CMD curl -sx localhost:8118 'https://check.torproject.org/' | \
            grep -qm1 Congratulations

VOLUME [ "/etc/tor", "/var/lib/tor", "/usr/share/metasploit-framework" ]
ENTRYPOINT [ "/sbin/tini", "--", "/usr/bin/init.sh" ]