#!/usr/bin/env bash

# Take input of the PCAP file to process
FILE="$1"

results_folder_uuid=$(date +%m%d%Y)
results_pcap_uuid=$(uuidgen)

tcpflow_db=/opt/drop_files/results/db/tcpflow/$results_folder_uuid/$results_pcap_uuid

# This will be the final output
db=/opt/drop_files/results/db/files/$results_folder_uuid/$results_pcap_uuid

mkdir -p $db
mkdir -p $tcpflow_db

# Run tcpflow and foremost to extract files
tcpflow -r "$FILE" -o "$tcpflow_db"

cat "$tcpflow_db"/* > "$tcpflow_db"/"$results_pcap_uuid"_tcpflow
find "$tcpflow_db"/ -not -name "$results_pcap_uuid"_tcpflow -type f -delete
foremost -i "$tcpflow_db"/"$results_pcap_uuid"_tcpflow -o "$db"/ -Q

# Find all files (recursively), except 'audit.txt'
check_files=$(find "$db" -type f ! -name "audit.txt")

# Check if any other files exist
if [[ -z "$check_files" ]]
then
  echo "[$(date)] Only audit.txt found for extracted files. Deleting "$db"" >> /opt/drop_files/scripts/logs/processed_pcaps.log
  rm -rf "$db"
else
  echo "[$(date)] Other files were extracted. Not deleting "$db"" >> /opt/drop_files/scripts/logs/processed_pcaps.log
fi

finished=$(date)
echo "[$finished] Processed file "$FILE" with tcpflow + foremost to extract files" >> /opt/drop_files/scripts/logs/processed_pcaps.log