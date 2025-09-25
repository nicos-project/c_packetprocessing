#!/bin/bash

# Run this script once after rebooting the system to setup the interface on the Mellanox NIC
# TODO: Maybe pass the iface as a command line option (useful when we test with both ports)

# Turn on the interface
sudo ip link set dev enp94s0f0np0 up
# Disable IPv6 on it
sudo sysctl -w net.ipv6.conf.enp94s0f0np0.disable_ipv6=1
# Put it in promiscuous mode
sudo ip link set dev enp94s0f0np0 promisc on
