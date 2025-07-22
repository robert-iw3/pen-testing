## Usage:

```sh
# interface to use, replace with yours
sudo podman build --build-arg interface=wlo1 -t trevor .

sudo podman run --rm -it --name trevor \
   --net=host \
   --cap-add=net_admin \
   --cap-add=net_raw \
   --cap-add=sys_nice \
   -d trevor

# start proxy
sudo podman exec trevor trevorproxy subnet -s dead:beef::0/64 -i wlo1
# note: detach or open another terminal

# test proxy
sudo podman exec trevor curl --proxy socks5://127.0.0.1:1080 -6 api64.ipify.org

# perform recon against url
sudo podman exec trevor trevorspray --recon evilcorp.com

# see product directories for more info
```