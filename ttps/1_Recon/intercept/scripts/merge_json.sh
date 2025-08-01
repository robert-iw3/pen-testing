#!/usr/bin/env bash

mkdir -p /opt/drop_files/results/json_db

jq -s . /opt/drop_files/results/json/*/""$1".json" > /opt/drop_files/results/json_db/""$1"".json

jq -s . /opt/drop_files/results/json/zeek/"$1"/*.log > /opt/drop_files/results/json_db/""$1""_zeek.json
