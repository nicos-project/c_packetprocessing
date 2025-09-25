#!/bin/bash
# Run this script once after rebooting the system to setup the interface on the Mellanox NIC
# Usage: ./setup_interface.sh <interface_name>
# Example: ./setup_interface.sh enp94s0f0np0

# Check if interface parameter is provided
if [ $# -eq 0 ]; then
    echo "Error: No interface specified"
    echo "Usage: $0 <interface_name>"
    echo "Example: $0 enp94s0f0np0"
    exit 1
fi

IFACE="$1"

# Validate that the interface exists
if ! ip link show "$IFACE" &> /dev/null; then
    echo "Error: Interface '$IFACE' not found"
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
    exit 1
fi

echo "Setting up interface: $IFACE"

# Turn on the interface
echo "Bringing up interface..."
sudo ip link set dev "$IFACE" up

# Disable IPv6 on it
echo "Disabling IPv6..."
sudo sysctl -w "net.ipv6.conf.$IFACE.disable_ipv6=1"

# Put it in promiscuous mode
echo "Enabling promiscuous mode..."
sudo ip link set dev "$IFACE" promisc on

echo "Interface $IFACE setup complete!"
