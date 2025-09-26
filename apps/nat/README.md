# NAT Application

This application implements a Network Address Translation (NAT) application on a Netronome Agilio CX40 NIC. It assumes one port as the LAN interface and another as the WAN interface on the Netronome NIC. The traffic incoming on the LAN port is translated and sent back on the same port for testing purposes. Similarly, the traffic on the WAN port is translated back and send on the same port for testing purposes. Currently, only UDP packets are supported.

## Compiling and loading
To build the application and load it on to the NIC:

`./build_and_load.sh`

On system reboots, initialize the Mellanox NIC using:

`./mlx_iface_init.sh <iface>`

## Testing
You can use `test_nat.py` to run correctness checks on the implementation. Ensure that both ports of the Netronome NIC are connected to the Mellanox NIC. The testing configuration uses a loopback setup where the Mellanox NIC sends UDP packets to Netronome LAN or WAN interface, the Netronome performs the NAT translation and mirrors packets back to the Mellanox NIC for verification. By default the testing script uses 1024 LAN clients and 63 ports for each client (64512 connections in total). You can run `sudo python3 test_nat.py 2` to run the test for 64512 connections for 2 packets in each direction (LAN to WAN and WAN to LAN).

Alternatively, you can test only the LAN to WAN conversion or WAN to LAN conversion based on parameters passed to the script. Run `sudo python3 test_nat.py --help` to see examples on how to do this.

## Notes
Using two packets for 64512 flows takes ~3 hours right now. Keep in mind that increasing the number of packets without decreasing the number of connections will result in more time. To configure the number of connections, you can edit the `num_ports_per_client` and `num_clients` variables in the script.
