#!/usr/bin/env bash

WATCH_DIR="/opt/drop_files/pcaps"
PROCESSED_DIR="/opt/drop_files/processed"

MAX_JOBS=15
count=0

mkdir -p "$WATCH_DIR" "$PROCESSED_DIR"

while true
do
  echo "Processing pcaps"

  files=$(find "$WATCH_DIR" -type f -iname '*.pcap')

  if [[ -z "$files" ]]
  then
    echo "No files to process. Cleaning up empty directories and files than Sleeping..."

    find "$WATCH_DIR" -mindepth 1 -depth -type d -empty -delete

    # Clean up empty directories, but ignore tcpflow and foremost directories along with bruteshark.
    # Tcpflow and foremost directories are cleaned up in extract_files.sh
    find "/opt/drop_files/results" -mindepth 1 -depth -type d -empty ! -name "/opt/drop_files/results/db/bruteshark*" ! -name "/opt/drop_files/results/db/files/*" ! -name "/opt/drop_files/results/db/tcpflow/*" -delete

    sleep 10
    continue
  fi

  while IFS= read -r file
  do

    echo "[$(date)] Starting processing: '$file'" >> /opt/drop_files/scripts/logs/monitor_files.log

    target="$PROCESSED_DIR/$(basename "$file")"
    if [[ -e "$target" ]]; then
      timestamp=$(date +%s)
      target="${PROCESSED_DIR}/$(basename "${file%.*}")_$timestamp.pcap"
    fi

    mv "$file" "$target"

    /bin/bash /opt/drop_files/scripts/parse_pcap.sh "$target" &
    /bin/bash /opt/drop_files/scripts/extract_files.sh "$target" &
    /bin/bash /opt/drop_files/scripts/run_bruteshark.sh "$target" &

    ((count++))

    if [ $((count % MAX_JOBS)) -eq 0 ]
    then
          echo "Reached maximum of number of processes to run in the background"
          echo "Waiting for them to finish in the background"
          wait # Wait for the current background processes to finish running before continuing
    fi
  done <<< "$files"

  echo "[$(date)] Finished processing pcaps. Waiting for last background processes to finish." >> /opt/drop_files/scripts/logs/monitor_files.log
  wait

  find "$WATCH_DIR" -mindepth 1 -depth -type d -empty -delete

  sleep 10
done