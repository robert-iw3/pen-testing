## Starting the VPN Proxy

### `vpn.config`

The main configuration file, contain the following values:

- `REGION`: (Optional) The default server is set to `ie33`. `REGION` should match the supported NordVPN `.opvn` server config.
- `USERNAME`: NordVPN username.
- `PASSWORD`: NordVPN password. Can set this variable via a file as the section below.
- `PROXY_MODE`: socks5 or http to use SOCKS5 or HTTP as proxy protocol.
- `PROTOCOL`: UDP or TCP which are supported by NordVPN.

## Environment variables

The environment variables needed for exposing the proxy to the local network:

- `PROXY_PORT`: Proxy port
- `HC_PORT`: Healthcheck port. A container internal port used by `wget` to check if the proxy is working through VPN.
- `LOCAL_NETWORK`: The CIDR mask of the local IP addresses (e.g. 192.168.0.1/24, 10.1.1.0/24) which will be acessing the proxy. This is so the response to a request can be returned to the client (i.e. your browser).
- `NORD_PROFILES_UPDATE`: Whether to update OpenVPN profiles or not. Possible values: yes|no.
- `EXT_IP`: Your external IP. Used only for healthcheck. You can get your current external IP on [ifconfig.co](https://ifconfig.co/ip)

These variables can be specified in the command line or in the `.env` file in the case of `docker-compose`.

### Set password via file

Passwords can be set using a `FILE__` prefixed environment variable where its value is path to the file contains the password:

```Shell
FILE__PASSWORD=/vpn/vpnpasswd
```

### build && run

```bash
podman build -t vpncontainer .

podman run -it --name vpn_proxy \
    --cap-add=net_admin \
    --device=/dev/net/tun \
    --dns=103.86.96.100 --dns=103.86.99.100 \
    --restart=always \
    -e "PROXY_PORT=3128" \
    -e "HC_PORT=8080"
    -e "EXT_IP=<get_yours_on_ifconfig.co/ip>"
    -e "LOCAL_NETWORK=192.168.0.1/24" \
    -e "FILE__PASSWORD=/vpn/vpnpasswd" \
    -v /etc/localtime:/etc/localtime:ro \
    -v ./vpn.config:/vpn/vpn.config:ro \
    -v "$(pwd)"/vpnpasswd:/vpn/vpnpasswd:ro \
    -p 3128:3128 \
    -d vpncontainer
```

## Connecting to the VPN Proxy

Set proxy on host machine to `socks5h://127.0.0.1:${PROXY_PORT}` or `socks5://127.0.0.1:${PROXY_PORT}`.

```Shell
curl -x socks5h://127.0.0.1:3128 -L ifconfig.co/json
```