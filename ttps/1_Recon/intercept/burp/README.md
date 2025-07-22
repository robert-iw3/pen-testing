## Burpsuite Pro container build

api-usage:

a) Modify config/user_options.json

```json
"api": {
    "enabled": true,
    "insecure_mode": true,
    "keys": [],
    "listen_mode": "all_interfaces",
    "port": 1337
}
```

Enter email/pass for your portswigger account and key

```sh
podman build -t burp-suite-pro \
  --build-arg PORTSWIGGER_EMAIL_ADDRESS="$PORTSWIGGER_EMAIL_ADDRESS" \
  --build-arg PORTSWIGGER_PASSWORD="$PORTSWIGGER_PASSWORD" .

export BURP_KEY="        "

podman run --rm --it \
  -p 8080:8080 \
  -p 1337:1337 \
  --name burp-pro \
  -e BURP_KEY=$BURP_KEY \
  -v "$(pwd):/home/burp/.java":Z \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -e DISPLAY=${DISPLAY} \
  -e XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR \
  --security-opt label=type:container_runtime_t \
  --userns=keep-id \
  --privileged \
  --net=host \
  -d burp-suite-pro
```

a) In Burp, open the 'Proxy' tab, and then the 'Options' tab.

b) Add a new 'Proxy Listener' by clicking the 'Add' button.

c) Enter the preferred port number, and make sure that 'Bind to address' is set to 'All interfaces'.

d) Verify that the proxy is working by running the following command on your host:

```sh
curl -x http://127.0.0.1:8080 http://example.com
```
