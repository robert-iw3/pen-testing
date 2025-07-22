```sh
# build
podman build -t tor-socks-proxy
# runtime
podman run --rm -it --restart=always --name tor-socks-proxy -p 127.0.0.1:9150:9150/tcp -d tor-socks-proxy
# use tor proxy
curl --socks5-hostname 127.0.0.1:9150 https://ipinfo.tw/ip
# dns over tor
podman run --rm -it --restart=always --name tor-socks-proxy -p 127.0.0.1:9150:9150/tcp -p 127.0.0.1:53:8853/udp -d tor-socks-proxy
# ip renewal
podman restart tor-socks-proxy
```