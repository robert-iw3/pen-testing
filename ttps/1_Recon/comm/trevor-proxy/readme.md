## Usage:

```sh
# interface to use, replace with yours
podman build --build-arg interface=wlo1 -t trevor .

podman run -it --name trevor \
    --cap-add=net_admin \
    --device /dev/net/tun \
    -p 127.0.0.1:1080:1080 -p 127.0.0.1:9050:9050 \
   -d trevor

# start proxy
podman exec trevor trevorproxy subnet -s dead:beef::0/64 -i wlo1
# note: detach or open another terminal

# test proxy
podman exec trevor curl --proxy socks5://127.0.0.1:1080 -6 api64.ipify.org
```