## nmap to find CVE's

```sh
# build nmap container
sudo podman build -t nmap .

# runtime nmap
sudo podman run --rm -it --name nmap \
    --net=host --cap-add=net_admin --cap-add=net_raw --cap-add=sys_nice \
    -d nmap

# execute cvss>=5.0 against target IP
sudo podman exec nmap nmap -sV --script vulners --script-args mincvss=5.0 !____ip of target___!

# execute vulscan script against target IP
sudo podman exec nmap nmap -sV --script=vulscan/vulscan.nse !___ip of target___!

# smoke test (you are allowed to scan vulnweb.com)
sudo podman exec nmap nmap -sV --script vulners --script-args mincvss=5.0 rest.vulnweb.com
sudo podman exec nmap nmap -sV --script=vulscan/vulscan.nse rest.vulnweb.com

# should take around 15sec's for each scan
```

### scan through tor
```bash
sudo podman build -t nmap -f proxy.Dockerfile

sudo podman run -it --name nmap \
    --net=host --cap-add=net_admin --cap-add=net_raw --cap-add=sys_nice \
    --device /dev/net/tun \
    -v /etc/resolv.conf:/etc/resolv.conf:ro \
    -d nmap

# open shell
sudo podman exec -it nmap /bin/bash

# verify traffic is routing through tor
curl --socks5 localhost:9050 --socks5-hostname localhost:9050 https://check.torproject.org/api/ip
curl --socks5 127.0.0.1:9050 --socks5-hostname localhost:9050 http://checkip.amazonaws.com/

# verify proxychains
proxychains curl http://checkip.amazonaws.com/

# execute cvss>=5.0 against target IP
proxychains nmap -sV --script vulners --script-args mincvss=5.0 !____ip of target___!

# execute vulscan script against target IP
proxychains nmap -sV --script=vulscan/vulscan.nse !___ip of target___!
```

## _SploitScan

Use SploitScan to find information of found CVE's and available exploits to start pen-testing.  Refer to documentation on how to use in the exploits/_SploitScan directory.