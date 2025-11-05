# Packet Steer Application

This application implements a design which allows incoming packets to be sent to different islands based on their four tuple hash. It is useful for applications which get bottlenecked by locks on a large global state and can benefit from a reducing the lock contention to island level states. For instance, we implement a stateless NAT using this which allows us to partition the NAT table among different islands and reduce the lock contention to a per island basis for the NAT table. This code supports three applications:
1. A stateless NAT (`nat.c`).
2. An echo application (`echo.c`) which basically echoes the packets back and does not really store any state.
3. Two kinds of stateless firewalls. The firewall in `firewall.c` uses a CAM based connection table whereas the firewall in `static_alloc_firewall.c` uses a static allocation based connection table.

## Compiling and loading
To build the stateless NAT application and load it on to the NIC:

`./build_and_load.sh nat`

To build the echo application and load it on to the NIC:

`./build_and_load.sh`

To build the firewall application and load it on to the NIC:

`./build_and_load.sh firewall`

To change between the static allocation and the CAM based variant, change the filename in Makefile to compile it with either the CAM or the static allocation based implementation.

## Testing
All testing scripts are present in the `testing` folder in the root directory of this repo.
### NAT
You can use the `nat-test.py` script to run correctness checks on the NAT implementation. By default the testing script uses 1024 LAN clients and 63 ports for each client (64512 connections in total). You can run `sudo python3 nat-test.py 2` to run the test for 64512 connections for 2 packets in each direction (LAN to WAN and WAN to LAN). With this implementation, you cannot test the WAN to LAN part individually since the WAN port assignment is not sequential.

### Firewall
To test the correctness of the firewall, you can run `firewall-test.py`. Remember to uncomment the lines in the code which talk to the testing script. This testing script checks for 65536 connections which is the max number the firewall supports. The test will take at least a few hours to complete.

### Echo
To test the echo application, you can use `echo-test.py` along with tcpdump to check the packets being echoed.

### TRex
You can also use `trex-test.py` to run performance tests on the NAT, echo and firewall implementations with different packets sizes and flow counts. For instance, to test the firewall, you can run `python3 trex-test.py firewall`.
