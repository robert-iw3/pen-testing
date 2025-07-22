#!/bin/bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ] ; then
  echo "❌ Run me as root"
    exit 1
fi

# env vars
BURP_HOST= #burp.domainname.io
BURP_PORT= #8080
PORTSWIGGER_EMAIL_ADDRESS= #your_portswigger_email
PORTSWIGGER_PASSWORD= #yo_pass
BURP_APIKEY= #someapikey
MODE= #http or https
WEBPORT= #"8080"
#declare -a TARGETS=(
#"google-gruyere.appspot.com"
#"testhtml5.vulnweb.com"
#"HackThisSite.org"
#"www.root-me.org")
#declare -a APP_NAME=(
#"google"
#"testhtml5"
#"hackthissite"
#"rootme")
RESULT_DIR=./
mkdir -p ./burp

DNF=$(which dnf)
APT=$(which apt)

if [ -n "$DNF" ] ; then
  dnf install -y podman
elif [ -n "$APT" ] ; then
  apt install -y podman
fi

# ----------------------------------------------------------------------------------------------------- burpsuite;
if command -v podman &> /dev/null; then
  echo "podman exists"
    podman build -t burp-suite-pro \
      --build-arg PORTSWIGGER_EMAIL_ADDRESS="$PORTSWIGGER_EMAIL_ADDRESS" \
      --build-arg PORTSWIGGER_PASSWORD="$PORTSWIGGER_PASSWORD" .
else
  echo "podman does not exist"
fi

if command -v podman &> /dev/null; then
  echo "podman exists"
    export BURP_KEY="$BURP_APIKEY"
    podman run --rm --it \
      -p 8080:8080 \
      -p 1337:1337 \
      --name burpsuite \
      -e BURP_KEY=$BURP_KEY \
      -v "$(pwd):/home/burp/.java":Z \
      -v /tmp/.X11-unix:/tmp/.X11-unix:Z \
      -e DISPLAY=${DISPLAY} \
      -e XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR \
      --security-opt label=type:container_runtime_t \
      --userns=keep-id \
      --privileged \
      --net=host \
      -d burp-suite-pro
else
  echo "podman does not exist"
fi

podman exec burpsuite mkdir -p $RESULT_DIR/burp

if [ "$MODE" = http ]; then
podman exec burpsuite curl -s -X POST "http://$BURP_HOST:$BURP_PORT/$BURP_APIKEY/v0.1/scan" \
-d "{\"scope\":{\"include\":[{\"rule\":\"http://$TARGET:80\"}],\"type\":\"SimpleScope\"},\"urls\":[\"http://$TARGET:$WEBPORT\"]}"

elif [ "$MODE" = https ]; then
podman exec burpsuite curl -s -X POST "http://$BURP_HOST:$BURP_PORT/$BURP_APIKEY/v0.1/scan" \
-d "{\"scope\":{\"include\":[{\"rule\":\"https://$TARGET:443\"}],\"type\":\"SimpleScope\"},\"urls\":[\"https://$TARGET:$WEBPORT\"]}"
fi

for a in {1..30}; do 
podman exec burpsuite echo -n "[-] SCAN #$a: "
podman exec burpsuite curl -sI "http://$BURP_HOST:$BURP_PORT/$BURP_APIKEY/v0.1/scan/$a" | grep HTTP | awk '{print $2}'
  podman exec burpsuite BURP_STATUS=$(curl -s http://$BURP_HOST:$BURP_PORT/$BURP_APIKEY/v0.1/scan/$a \
    | grep -o -P "crawl_and_audit.{1,100}" | cut -d\" -f3 | grep "remaining")
while [[ ${#podman exec burpsuite BURP_STATUS} -gt "5" ]]; do 
  podman exec burpsuite BURP_STATUS=$(curl -s http://$BURP_HOST:$BURP_PORT/$BURP_APIKEY/v0.1/scan/$a \
    | grep -o -P "crawl_and_audit.{1,100}" | cut -d\" -f3 | grep "remaining")
  podman exec burpsuite BURP_STATUS_FULL=$(curl -s http://$BURP_HOST:$BURP_PORT/$BURP_APIKEY/v0.1/scan/$a \
    | grep -o -P "crawl_and_audit.{1,100}" | cut -d\" -f3)
  podman exec burpsuite echo "[i] STATUS: $BURP_STATUS_FULL"
  podman exec burpsuite sleep 15
	done
done

for a in {1..30}; do
  podman exec burpsuite curl -s "http://$BURP_HOST:$BURP_PORT/$BURP_APIKEY/v0.1/scan/$a" \
    | jq '.issue_events[].issue | "[" + .severity + "] " + .name + " - " + .origin + .path' | sort -u | sed 's/\"//g' \
    | tee $RESULT_DIR/web/burpsuite-$TARGET-$a.log
done
podman cp burpsuite:$RESULT_DIR/burp $RESULT_DIR/burp
echo "---------------------------------------------burp scan; done."
