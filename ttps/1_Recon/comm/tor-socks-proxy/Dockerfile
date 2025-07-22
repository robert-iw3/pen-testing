FROM docker.io/alpine:3.22

RUN echo '@edge https://dl-cdn.alpinelinux.org/alpine/edge/community' >> /etc/apk/repositories ; \
    echo '@edge https://dl-cdn.alpinelinux.org/alpine/edge/testing'   >> /etc/apk/repositories ; \
    apk -U upgrade ; \
    apk -v add tor@edge obfs4proxy@edge curl ; \
    chmod 700 /var/lib/tor ; \
    rm -rf /var/cache/apk/* ; \
    tor --version

COPY --chown=tor:root torrc /etc/tor/

USER tor
EXPOSE 8853/udp 9150/tcp

CMD ["/usr/bin/tor", "-f", "/etc/tor/torrc"]
