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

iface = "ens3f0np0"

# this is annoying but the receiver will
# set this flag when it has failed to tell the sender to exit
# TODO: exit the sender gracefully
exit_sender = False

class PacketSender(threading.Thread):
    def __init__(self, packets_per_port, interface=None):
        threading.Thread.__init__(self)
        self.interface = interface
        self.sender_thread = None
        self.num_packets_per_port = packets_per_port

    def send_packets(self):
        base_ip_hex = 0xC0A80101
        count = 10
        cur_count = 0
        while cur_count < count:
            # Calculate new IP by adding client_idx to the base IP
            new_ip_hex = base_ip_hex
            # Convert back to dotted decimal notation
            src_ip = f"{(new_ip_hex >> 24) & 0xFF}.{(new_ip_hex >> 16) & 0xFF}.{(new_ip_hex >> 8) & 0xFF}.{new_ip_hex & 0xFF}"
            src_port = 49000
            dst_ip = "12.11.10.9"
            dst_port = 80
            p = Ether() / IP(src = src_ip, dst = dst_ip) / UDP(sport = src_port, dport = dst_port) / Raw(b"\x00" * 18)
            if exit_sender:
                return
            sendp(p, iface=iface, verbose=0)
            cur_count += 1

    def run(self):
        """Start packet sending in a separate thread"""
        global exit_sender

        try:
            self.send_packets()

        except Exception as e:
            print(e)

class PacketReceiver(threading.Thread):
    def __init__(self, num_packets, interface=None):
        threading.Thread.__init__(self)
        self.interface = interface
        self.receiving = False
        self.packet_count = 0
        self.receiver_thread = None
        self.raw_socket = None
        self.packets_per_port = num_packets

    def parse_ethernet_header(self, data):
        """Parse Ethernet header"""
        # Ethernet header is 14 bytes
        eth_header = struct.unpack('!6s6sH', data[:14])
        dest_mac = ':'.join(['%02x' % b for b in eth_header[0]])
        src_mac = ':'.join(['%02x' % b for b in eth_header[1]])
        eth_type = eth_header[2]
        return dest_mac, src_mac, eth_type, data[14:]

    def parse_ip_header(self, data):
        """Parse IP header"""
        if len(data) < 20:
            return None

        # IP header first 20 bytes
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])

        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        header_length = ihl * 4

        if version != 4:  # Only handle IPv4 for now
            return None

        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])

        return {
            'version': version,
            'header_length': header_length,
            'protocol': protocol,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'payload': data[header_length:]
        }

    def parse_udp_header(self, data):
        """Parse UDP header"""
        if len(data) < 8:
            return None

        udp_header = struct.unpack('!HHHH', data[:8])
        src_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]

        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'length': length,
            'payload': data[8:]
        }

    def is_valid_client_ip(self, dest_ip, network_ip="192.168.0.0", prefix_length=16):
        try:
            # Convert IP addresses to integers
            def ip_to_int(ip):
                parts = ip.split('.')
                return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
                       (int(parts[2]) << 8) + int(parts[3])

            dest_int = ip_to_int(dest_ip)
            network_int = ip_to_int(network_ip)

            # Create subnet mask
            mask = 0xFFFFFFFF << (32 - prefix_length)

            return (dest_int & mask) == network_int
        except (ValueError, IndexError):
            return False

    def display_packet(self, data, packet_size, verbose=False):
        """Display packet information"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if verbose:
            print(f"\n[{self.packet_count:04d}] {timestamp} - Packet received:")
            print(f"  Size: {packet_size} bytes")

        try:
            # Parse Ethernet header
            dest_mac, src_mac, eth_type, payload = self.parse_ethernet_header(data)
            if verbose:
                print(f"  Ethernet: {src_mac} -> {dest_mac} (Type: 0x{eth_type:04x})")

            # Handle different Ethernet types
            if eth_type == 0x0800:  # IPv4
                ip_info = self.parse_ip_header(payload)
                if ip_info:
                    if verbose:
                        print(f"  IPv4: {ip_info['src_ip']} -> {ip_info['dest_ip']} (Protocol: {ip_info['protocol']})")

                    if ip_info['protocol'] == 17:  # UDP
                        udp_info = self.parse_udp_header(ip_info['payload'])
                        if udp_info:
                            if verbose:
                                print(f"  UDP: {udp_info['src_port']} -> {udp_info['dest_port']} (Length: {udp_info['length']})")
                                print(f"  Data: {udp_info['payload']}")

        except Exception as e:
            print(f"  Error parsing packet: {e}")
            # Still show raw data on parse error
            raw_preview = data[:64]
            hex_data = ' '.join([f'{b:02x}' for b in raw_preview])
            print(f"  Raw data (first 64 bytes): {hex_data}")
            return -1

    def create_raw_socket(self):
        """Create raw socket for packet reception"""
        try:
            # Create raw socket - captures only IP packets (0x0800)
            self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
            self.raw_socket.settimeout(1.0)

            # Bind to specific interface if provided
            if self.interface:
                self.raw_socket.bind((self.interface, 0))

            return True
        except Exception as e:
            print(f"Error creating raw socket: {e}")
            return False

    def run(self):
        global exit_sender
        """Start packet reception in a separate thread"""
        if self.receiving:
            print("Packet receiver is already running!")
            return False

        if not self.create_raw_socket():
            print("Failed to create raw socket!")
            return False

        self.receiving = True
        self.packet_count = 0

        try:
            while self.receiving:
                try:
                    data, addr = self.raw_socket.recvfrom(65535)
                    if data:
                        if self.display_packet(data, len(data), True) == -1:
                            self.receiving = False
                            exit_sender = True
                except socket.timeout:
                    # Timeout is normal, just continue the loop
                    continue
        except Exception as e:
            if self.receiving:
                print(f"Error receiving packets: {e}")

    def cleanup(self):
        # Close socket
        if self.raw_socket:
            self.raw_socket.close()
            self.raw_socket = None

    def stop_running(self):
        print(f"\nStopping packet reception... (Received {self.packet_count} packets)")
        self.receiving = False

def start_test():
    try:
        # receiver = PacketReceiver(iface)
        # receiver.start()

        # sleep for 2 seconds before starting the sender
        time.sleep(2)
        sender = PacketSender(iface)

        # this function starts the sender in a separate thread
        sender.start()
        sender.join()

        # receiver.stop_running()
        # receiver.join()
        # the receiver also verifies that the test ran successfully
        # in case of ltw or wtl modes
        # receiver.cleanup()

    except KeyboardInterrupt:
        print("\nReceived interrupt signal...")
    except Exception as e:
        print(f"Unexpected error: {e}")

def main():
        start_test()

if __name__ == "__main__":
    main()
