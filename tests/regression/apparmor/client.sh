#!/bin/bash

NET_NS=$1
IP=$2
PORT=$3
REQUEST_FILE=$4

output=$(ip netns exec "$NET_NS" nc -w 1 -q 1 "${IP}" "${PORT}" < "$REQUEST_FILE" 2>&1)

read -r -a http_fields <<< "$output"

status_code="${http_fields[1]}"

if [ "$status_code" = 200 ]; then
    echo "PASS"
else
    echo "FAIL $output"
fi
