# NAT Application

This application implements a Network Address Translation (NAT) application on a Netronome Agilio CX40 NIC. It assumes one port as the LAN interface and another as the WAN interface on the Netronome NIC. The traffic incoming on the LAN port is translated and sent back on the same port for testing purposes. Similarly, the traffic on the WAN port is translated back and send on the same port for testing purposes. Currently, only UDP packets are supported.

## Compiling and loading
To build the application and load it on to the NIC:

`./build_and_load.sh`

On system reboots, initialize the Mellanox NIC using:

`./mlx_iface_init.sh`

## Testing
You can use `test_nat.py` to run correctness checks on the implementation. Ensure that both ports of the Netronome NIC are connected to the Mellanox NIC. The testing configuration uses a loopback setup where the Mellanox NIC sends UDP packets to Netronome LAN or WAN interface, the Netronome performs the NAT translation and mirrors packets back to the Mellanox NIC for verification. By default the testing script uses 1024 LAN clients and 63 ports for each client (64512 connections in total). You can run `sudo python3 test_nat.py 2` to run the test for 64512 connections for 2 packets in each direction (LAN to WAN and WAN to LAN).

### LAN to WAN Test Validation
Run `sudo python3 test_nat.py ltw 2` to test only the LAN to WAN conversion.

### WAN to LAN Test Validation
Run `sudo python3 test_nat.py wtl 2` to test only the WAN to LAN conversion. Make sure you ran the LAN to WAN conversion test before.

### Notes
Keep in mind that increasing the number of packets without decreasing the number of connections will result in more time. To configure the number of connections, you can edit the `num_ports_per_client` and `num_clients` variables accordingly in the script.
