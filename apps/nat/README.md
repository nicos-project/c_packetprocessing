# NAT Application

This application implements a NAT application on a Netronome Agilio CX40. It assumes one port as the LAN and another as the WAN on the Netronome NIC. The traffic incoming on the LAN port is translated and sent back again on the same port.

## Compiling and loading
To build the application and load it on to the NIC:

`./build_and_load.sh`

On reboots, initialize the Mellanox NIC using:

`./mlx_iface_init.sh`

## Testing
You can use test_nat.py to run correctness checks on the implementation. Ensure that both ports of the Netronome NIC are connected to another NIC. The tests have been performed using a an MLX CX6 on Ubuntu 18.04. The
