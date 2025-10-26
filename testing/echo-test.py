#!/usr/bin/env python3

from scapy.all import *
from time import sleep
import sys

# Receiver specific includes
import socket
import struct
import threading
import os
from datetime import datetime

# This script is used to test very simple echo
# functionality. It does not receive packets.
# To view the packets being received, use tcpdump
# like: sudo tcpdump -i ens3f0np0 -e -vvx
# Change the iface variable below accordingly.

iface = "ens3f0np0"

class PacketSender(threading.Thread):
    def __init__(self, packets_per_port, interface=None):
        threading.Thread.__init__(self)
        self.interface = interface
        self.sender_thread = None
        self.num_packets_per_port = packets_per_port

    def send_packets(self):
        base_ip_hex = 0xC0A80101
        count = 5
        cur_count = 0
        num_flows = 1
        cur_flow = 0
        while cur_count < count:
            # Calculate new IP by adding client_idx to the base IP
            new_ip_hex = base_ip_hex
            # Convert back to dotted decimal notation
            src_ip = f"{(new_ip_hex >> 24) & 0xFF}.{(new_ip_hex >> 16) & 0xFF}.{(new_ip_hex >> 8) & 0xFF}.{new_ip_hex & 0xFF}"
            src_port = 49000 + cur_flow
            dst_ip = "12.11.10.9"
            dst_port = 80
            p = Ether() / IP(src = src_ip, dst = dst_ip) / UDP(sport = src_port, dport = dst_port) / Raw(b"\x00" * 18)
            sendp(p, iface=iface, verbose=0)
            cur_count += 1
            cur_flow = (cur_flow + 1) % num_flows

    def run(self):
        """Start packet sending in a separate thread"""
        try:
            self.send_packets()

        except Exception as e:
            print(e)

def start_test():
    try:
        # sleep for 2 seconds before starting the sender
        time.sleep(2)
        sender = PacketSender(iface)

        # this function starts the sender in a separate thread
        sender.start()
        sender.join()

    except KeyboardInterrupt:
        print("\nReceived interrupt signal...")
    except Exception as e:
        print(f"Unexpected error: {e}")

def main():
        start_test()

if __name__ == "__main__":
    main()
