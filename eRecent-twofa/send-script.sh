#!/bin/bash

INTERFACE=${1:-veth-send}

for i in {1..16}; do
    echo "Starting replay #$i on $INTERFACE..."
    sudo tcpreplay --intf1=$INTERFACE --topspeed ../1.pcap &
    sleep 30
done

echo "All replays started. Waiting for background processes..."
wait
echo "All replays completed."