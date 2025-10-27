# Packet Steer Application

This application implements a design which allows incoming packets to be sent to different islands based on their four tuple hash. It is useful for applications which get bottlenecked by locks on a large global state and can benefit from a reducing the lock contention to island level states. For instance, we implement a stateless NAT using this which allows us to partition the NAT table among different islands and reduce the lock contention to a per island basis for the NAT table. This code supports two applications -- one is a stateless NAT (`nat.c`) and another is a simple Tx application (`simple_tx.c`) which basically echoes the packets back and does not really store any state.

## Compiling and loading
To build the stateless NAT application and load it on to the NIC:

`./build_and_load.sh nat`

To build the echo application and load it on to the NIC:

`./build_and_load.sh`

## Testing
You can use the `nat-test.py` script to run correctness checks on the NAT implementation. By default the testing script uses 1024 LAN clients and 63 ports for each client (64512 connections in total). You can run `sudo python3 nat-test.py 2` to run the test for 64512 connections for 2 packets in each direction (LAN to WAN and WAN to LAN). With this implementation, you cannot test the WAN to LAN part individually since the WAN port assignment is not sequential.

To test the echo application, you can use `echo-test.py` along with tcpdump to check the packets being echoed.

You can also use `trex-test.py` to test the NAT and echo implementations with different packets sizes and flow counts.

All testing scripts are present in the `testing` folder in the root directory of this repo.
