#!/bin/bash
set -e
sudo ip link add veth-send type veth peer name veth-recv || true
sudo ip link set veth-send address ea:d9:d9:8f:0d:4f
sudo ip link set veth-recv address 1a:43:4f:ac:3f:05
sudo ip link set veth-send up
sudo ip link set veth-recv up
echo "veth pair created: veth-send <--> veth-recv"
