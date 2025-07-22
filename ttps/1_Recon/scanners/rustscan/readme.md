## rustscan

```sh
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where scanning meets swagging. 😎
```

```sh
# change dns, using quad9 - change this to nameserver other than ISP
sudo mv /etc/resolv.conf /etc/resolv.conf.bak
sudo touch /etc/resolv.conf
echo -ne 'nameserver 9.9.9.9\nnameserver 149.112.112.112' | sudo tee -a /etc/resolv.conf

# build the image
sudo podman build -t rustscan .

# clear images/build content
sudo podman system prune -a

# example command to run the container
sudo podman run --rm -it --name rustscan \
   -v /etc/resolv.conf:/etc/resolv.conf:ro \
   --net=host --cap-add=net_admin --cap-add=net_raw --cap-add=sys_nice \
   -d rustscan

# example command to run the container with a specific target subnet (e.g. local home ethernet cidr)
# full subnet scan
sudo podman exec rustscan rustscan --addresses 192.168.1.0/24 -t 500 -b 1500 -- -A

# If you want to scan ports in a random order (which will help with not setting off firewalls) run RustScan like this:
# select target and port range with randomization
sudo podman exec rustscan rustscan -a 192.168.1.0/24 --range 1-1000 --scan-order "Random"
```

### scanning through tor
```bash
sudo podman build -t rustscan -f proxy.Dockerfile

sudo podman run --rm -it --name rustscan \
   -v /etc/resolv.conf:/etc/resolv.conf:ro \
   --net=host --cap-add=net_admin --cap-add=net_raw --cap-add=sys_nice \
   -d rustscan

podman exec -it rustscan /bin/bash

# verify tor/proxychains
curl --socks5 localhost:9050 --socks5-hostname localhost:9050 https://check.torproject.org/api/ip
proxychains curl http://checkip.amazonaws.com/

# scan examples
proxychains rustscan --addresses XXX.XX.XXX.XX -t 500 -b 1500 -- -A
proxychains rustscan -a XXX.XX.XXX.XX --range 1-1000 --scan-order "Random"
```