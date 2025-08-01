#!/usr/bin/env bash

# Take input of the PCAP file to process
FILE="$1"

results_folder_uuid=$(date +%m%d%Y)
results_pcap_uuid=$(uuidgen)

results_folder=/opt/drop_files/results/$results_folder_uuid/$results_pcap_uuid
json_folder=/opt/drop_files/results/json/$results_folder_uuid/$results_pcap_uuid

# This will be the final output
db=/opt/drop_files/results/db/pcap_analysis/$results_folder_uuid/$results_pcap_uuid

mkdir -p $db

# Yes I hate it very much
mkdir -p $json_folder/zeek
mkdir -p $json_folder/dsniff
mkdir -p $json_folder/p0f
mkdir -p $json_folder/ntlmraw_unhide

# Create folders for each tool (so we can turn the raw output to json later on)
# Yes. I hate it.
mkdir -p $results_folder/dsniff
mkdir -p $results_folder/p0f
mkdir -p $results_folder/ntlmraw_unhide

current=$(date)
echo "[$current] Processing file "$FILE"" >> /opt/drop_files/scripts/logs/processed_pcaps.log

if [[ -d "$json_folder/zeek" && -w "$json_folder/zeek" ]]
then
	cd $json_folder/zeek
  	/opt/zeek/bin/zeek -C \
    	LogAscii::use_json=T \
    	-r "$FILE"
	cd $results_folder
else
  echo "Error: Cannot write to $json_folder/zeek" >> /opt/drop_files/scripts/logs/processed_pcaps.log
fi

dsniff -p "$FILE" -w $results_folder/dsniff/dsniff_results.log > /dev/null &
p0f -r "$FILE" -o $results_folder/p0f/p0f.log > /dev/null &

python3 /opt/NTLMRawUnHide.py -q -i "$FILE" -o $results_folder/ntlmraw_unhide/ntlmraw_unhide.log > /dev/null &

# Wait for all the background processes to be done
wait

echo "[$(date)] Finished running tools on file "$FILE"" >> /opt/drop_files/scripts/logs/processed_pcaps.log

# Start checking for logs
check_p0f=$(find $results_folder -type f -name "p0f.log")
check_dsniff=$(find $results_folder -type f -name "dsniff_results.log")
check_ntlmrawunhide=$(find $results_folder -type f -name "ntlmraw_unhide.log")

# If the logs are not empty
if [[ -n "$check_p0f" && -s "$check_p0f" ]]
then
	jq -Rn '[.,inputs] | map({p0f: .})' "$check_p0f" > $json_folder/p0f/$results_pcap_uuid.json
else
	echo "[$(date)] No p0f output for $FILE" >> /opt/drop_files/scripts/logs/processed_pcaps.log
	rm -rf $results_folder/p0f
fi

if [[ -n "$check_dsniff" && -s "$check_dsniff" ]]
then
	jq -Rn '[.,inputs] | map({dsniff: .})' "$check_dsniff" > $json_folder/dsniff/$results_pcap_uuid.json
else
	echo "[$(date)] No dsniff output for $FILE" >> /opt/drop_files/scripts/logs/processed_pcaps.log
	rm -rf $results_folder/dsniff
fi

if [[ -n "$check_ntlmrawunhide" && -s "$check_ntlmrawunhide" ]]
then
	jq -Rn '[.,inputs] | map({ntlm: .})' "$check_ntlmrawunhide" > $json_folder/ntlmraw_unhide/$results_pcap_uuid.json
else
	echo "[$(date)] No ntlmraw_unhide output for $FILE" >> /opt/drop_files/scripts/logs/processed_pcaps.log
	rm -rf $results_folder/ntlmraw_unhide
fi

# Merge json files to get final output.
/opt/drop_files/scripts/merge_json.sh "$json_folder" "$db" "$results_pcap_uuid"

finished=$(date)
echo "[$finished] Processed file "$FILE"" >> /opt/drop_files/scripts/logs/processed_pcaps.log

