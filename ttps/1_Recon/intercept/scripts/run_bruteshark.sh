#!/usr/bin/env bash

# Take input of the PCAP file to process
FILE="$1"

results_folder_uuid=$(date +%m%d%Y)
results_pcap_uuid=$(uuidgen)

# This will be the final output
db=/opt/drop_files/results/db/bruteshark/$results_folder_uuid/$results_pcap_uuid
mkdir -p $db

brutesharkcli -i "$FILE" -m Credentials,NetworkMap,DNS -o "$db" > /dev/null

finished=$(date)
echo "[$finished] Processing file "$FILE" with bruteshark" >> /opt/drop_files/scripts/logs/processed_pcaps.log