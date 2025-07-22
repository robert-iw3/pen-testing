#!/bin/bash
# example script to scan url's with project discovery tools

OFFLOAD_DIR=./

declare -a D_URL=(
"http://testhtml5.vulnweb.com"
"https://hackerone.com"
"https://www.itsecgames.com/")
declare -a R_NAME=(
"vulnweb"
"hackerone"
"bwapp")

podman build -t discovery .
podman image prune -f
podman run --rm -it --name discovery -d discovery

# scans

for ((i=0; i<${#D_URL[@]}; i++)); do
    podman exec -it discovery httpx -u ${D_URL[$i]} -csv -o /home/discovery/${R_NAME[$i]}_httpx.csv
done

for ((i=0; i<${#D_URL[@]}; i++)); do
    podman exec -it discovery subfinder -d ${D_URL[$i]} -o /home/discovery/${R_NAME[$i]}_subfinder.log -v
done

for ((i=0; i<${#D_URL[@]}; i++)); do
    podman exec -it discovery naabu -host ${D_URL[$i]} -csv -o /home/discovery/${R_NAME[$i]}_naabu.csv
done

for ((i=0; i<${#D_URL[@]}; i++)); do
    podman exec -it discovery katana -u ${D_URL[$i]} -o /home/discovery/${R_NAME[$i]}_katana.log
done

#get results
podman cp discovery:/home/discovery ${OFFLOAD_DIR}