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

num_ports_per_client = 4
num_clients = 1

num_syn_pkts = 0

iface = "ens3f0np0"
lan_src_port_start = 0

wan_ip = "54.239.28.85"
# Avoiding the well-known ports (0-1023)
wan_dst_port_start = 1024

# Assume all clients talk to the same application on the public internet
# This seems like a strong assumption, but the application clients talk to doesn't
# matter for NAT at all
public_app_ip = "12.11.10.9"
public_app_port = 80

lan_to_wan_recv_stats = {}
wan_to_lan_recv_stats = {}

lan_to_wan_send_stats = {}
wan_to_lan_send_stats = {}

# this is annoying but the receiver will
# set this flag when it has failed to tell the sender to exit
# TODO: exit the sender gracefully
exit_sender = False

def print_help():
    help_text = """
NAT Traffic Tester

Usage:
    python3 nat-test.py <packets_per_port>                  # Test both LAN to WAN and WAN to LAN
    python3 nat-test.py ltw <packets_per_port>              # Test LAN to WAN only
    python3 nat-test.py wtl <packets_per_port>              # Test WAN to LAN only
    python3 nat-test.py -h | --help                         # Show this help message

Arguments:
    ltw                 LAN to WAN traffic mode
    wtl                 WAN to LAN traffic mode
    packets_per_port    Number of packets to send per port (required)

Examples:
    python3 nat-test.py 10           # Send 10 packets per port in both directions
    python3 nat-test.py ltw 25       # Send 25 packets per port from LAN to WAN
    python3 nat-test.py wtl 5        # Send 5 packets per port from WAN to LAN
"""
    print(help_text)

def parse_arguments():
    # Handle help requests
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_help()
        sys.exit(0)

    # Remove script name from arguments
    args = sys.argv[1:]

    mode = 'both'  # default mode
    packets_per_port = None

    try:
        if len(args) == 1:
            # Format: python3 nat-test.py <packets>
            packets_per_port = int(args[0])
            mode = 'both'

        elif len(args) == 2:
            # Format: python3 nat-test.py <mode> <packets>
            direction = args[0].lower()
            packets_per_port = int(args[1])

            if direction == 'ltw':
                mode = 'ltw'
            elif direction == 'wtl':
                mode = 'wtl'
            else:
                raise ValueError(f"Invalid mode '{direction}'. Use 'ltw' or 'wtl'")
        else:
            raise ValueError("Invalid number of arguments")

    except ValueError as e:
        if "invalid literal for int()" in str(e):
            print("Error: packets_per_port must be a valid integer")
        else:
            print(f"Error: {e}")
        print("\nUse 'python3 nat-test.py --help' for usage information")
        sys.exit(1)

    # Validate packet count
    if packets_per_port <= 0:
        print("Error: packets_per_port must be greater than 0")
        sys.exit(1)

    return mode, packets_per_port

class PacketSender(threading.Thread):
    def __init__(self, mode, packets_per_port, stf_mode, interface=None):
        threading.Thread.__init__(self)
        self.interface = interface
        self.sender_thread = None
        self.mode = mode
        self.use_tcp = stf_mode
        self.num_packets_per_port = packets_per_port

    def send_syn_packets(self):
        base_ip_hex = 0xC0A80101
        for client_idx in range(0, num_clients):
            for port_idx in range(0, num_ports_per_client):
                # Calculate new IP by adding client_idx to the base IP
                new_ip_hex = base_ip_hex + client_idx
                # Convert back to dotted decimal notation
                src_ip = f"{(new_ip_hex >> 24) & 0xFF}.{(new_ip_hex >> 16) & 0xFF}.{(new_ip_hex >> 8) & 0xFF}.{new_ip_hex & 0xFF}"
                src_port = lan_src_port_start + port_idx
                dst_ip = public_app_ip
                dst_port = public_app_port
                p = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / Raw(b"\x00" * 18)
                sendp(p, iface=iface, verbose=0)
                print(f"{src_ip}:{src_port} -> {self.num_packets_per_port}")

    def send_lan_to_wan_traffic(self):
        if self.use_tcp:
            print("Sending SYN Packets")
            self.send_syn_packets()

        print("Starting LAN to WAN traffic ======>")
        print(f"LAN to WAN sender stats (Source IP address and {'TCP' if self.use_tcp else 'UDP'} port):")
        # Base IP: 192.168.1.1 as hex = 0xC0A80101
        # Avoiding the 192.168.0.x subnet since that is a valid subnet in pikachu
        base_ip_hex = 0xC0A80101
        for client_idx in range(0, num_clients):
            for port_idx in range(0, num_ports_per_client):
                # Calculate new IP by adding client_idx to the base IP
                new_ip_hex = base_ip_hex + client_idx
                # Convert back to dotted decimal notation
                src_ip = f"{(new_ip_hex >> 24) & 0xFF}.{(new_ip_hex >> 16) & 0xFF}.{(new_ip_hex >> 8) & 0xFF}.{new_ip_hex & 0xFF}"
                src_port = lan_src_port_start + port_idx
                dst_ip = public_app_ip
                dst_port = public_app_port

                # Create packet based on protocol type
                if self.use_tcp:
                    p = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags=0) / Raw(b"\x00" * 18)
                else:
                    p = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(b"\x00" * 18)

                for i in range(0, self.num_packets_per_port):
                    if exit_sender:
                        return
                    sendp(p, iface=iface, verbose=0)
                print(f"{src_ip}:{src_port} -> {self.num_packets_per_port}")
                lan_to_wan_send_stats[f"{src_ip}:{src_port}"] = self.num_packets_per_port

    def send_wan_to_lan_traffic(self):
        print("Starting WAN to LAN traffic ======>")
        print(f"WAN to LAN sender stats (Destination IP address and {'TCP' if self.use_tcp else 'UDP'} port):")
        if len(lan_to_wan_recv_stats) > 0:
            # send what we received during LAN to WAN traffic
            # this is useful in case we use a steering island to assign
            # packets to different islands since each island would be sending
            # from it's own WAN port start range
            ports = [int(key.split(':')[1]) for key in lan_to_wan_recv_stats.keys()]
            for port in ports:
                src_ip = public_app_ip
                src_port = public_app_port
                dst_ip = wan_ip
                dst_port = port

                # Create packet based on protocol type
                if self.use_tcp:
                    p = Ether() / IP(src=src_ip, dst=wan_ip) / TCP(sport=src_port, dport=dst_port, flags = 0) / Raw(b"\x00" * 18)
                else:
                    p = Ether() / IP(src=src_ip, dst=wan_ip) / UDP(sport=src_port, dport=dst_port) / Raw(b"\x00" * 18)

                for i in range(0, self.num_packets_per_port):
                    if exit_sender:
                        return
                    sendp(p, iface=iface, verbose=0)
                print(f"{wan_ip}:{dst_port} -> {self.num_packets_per_port}")
                wan_to_lan_send_stats[f"{wan_ip}:{dst_port}"] = self.num_packets_per_port
        else:
            total_ports = num_ports_per_client * num_clients
            for port_idx in range(0, total_ports):
                src_ip = public_app_ip
                src_port = public_app_port
                dst_ip = wan_ip
                dst_port = wan_dst_port_start + port_idx

                # Create packet based on protocol type
                if self.use_tcp:
                    p = Ether() / IP(src=src_ip, dst=wan_ip) / TCP(sport=src_port, dport=dst_port, flags=0) / Raw(b"\x00" * 18)
                else:
                    p = Ether() / IP(src=src_ip, dst=wan_ip) / UDP(sport=src_port, dport=dst_port) / Raw(b"\x00" * 18)

                for i in range(0, self.num_packets_per_port):
                    if exit_sender:
                        return
                    sendp(p, iface=iface, verbose=0)
                print(f"{wan_ip}:{dst_port} -> {self.num_packets_per_port}")
                wan_to_lan_send_stats[f"{wan_ip}:{dst_port}"] = self.num_packets_per_port

    def run(self):
        """Start packet sending in a separate thread"""
        global exit_sender

        try:
            if self.mode == "ltw":
                return self.send_lan_to_wan_traffic()
            elif self.mode == "wtl":
                return self.send_wan_to_lan_traffic()

        except Exception as e:
            print(e)

class PacketReceiver(threading.Thread):
    def __init__(self, mode, num_packets, interface=None):
        threading.Thread.__init__(self)
        self.interface = interface
        self.receiving = False
        self.packet_count = 0
        self.receiver_thread = None
        self.raw_socket = None
        self.mode = mode
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

    def parse_tcp_header(self, data):
        """Parse TCP header"""
        if len(data) < 20:  # Minimum TCP header size is 20 bytes
            return None

        # Unpack the fixed portion of TCP header (first 20 bytes)
        tcp_header = struct.unpack('!HHIIBBHHH', data[:20])

        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        offset_reserved = tcp_header[4]
        flags = tcp_header[5]
        window = tcp_header[6]
        checksum = tcp_header[7]
        urgent_ptr = tcp_header[8]

        # Data offset is in the upper 4 bits, represents number of 32-bit words
        data_offset = (offset_reserved >> 4) * 4

        # Extract individual flag bits
        flag_fin = flags & 0x01
        flag_syn = flags & 0x02
        flag_rst = flags & 0x04
        flag_psh = flags & 0x08
        flag_ack = flags & 0x10
        flag_urg = flags & 0x20

        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'data_offset': data_offset,
            'flags': {
                'fin': flag_fin,
                'syn': flag_syn,
                'rst': flag_rst,
                'psh': flag_psh,
                'ack': flag_ack,
                'urg': flag_urg
            },
            'window': window,
            'checksum': checksum,
            'urgent_ptr': urgent_ptr,
            'payload': data[data_offset:]
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
        global num_syn_pkts
        """Display packet information"""
        expected_total_pkts = num_clients * num_ports_per_client * self.packets_per_port
        if self.packet_count > expected_total_pkts:
            raise Exception("Received more packets than expected")

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

                            # Checks for packets mirrored on the LAN port
                            # 1. The source IP is swapped with the WAN IP
                            # 2. The source UDP port is swaped with a valid WAN port. It should be in the range [1024, 65535]
                            if self.mode == "ltw":
                                if udp_info['payload'][0:4] == b'\xff\xff\xff\xff':
                                    raise Exception("NAT table ran out of buckets")
                                if udp_info['src_port'] < wan_udp_dst_port_start:
                                    raise Exception(f"Received an invalid port = {udp_info['src_port']}")
                                if ip_info['src_ip'] == wan_ip:
                                    ltw_key = f"{ip_info['src_ip']}:{udp_info['src_port']}"
                                    if ltw_key in lan_to_wan_recv_stats:
                                        lan_to_wan_recv_stats[ltw_key] += 1
                                    else:
                                        lan_to_wan_recv_stats[ltw_key] = 1
                                    if lan_to_wan_recv_stats[ltw_key] > self.packets_per_port:
                                        raise Exception(f"Received invalid number of packets = {ltw_key}:{lan_to_wan_recv_stats[ltw_key]}")
                                else:
                                    raise Exception(f"Received an invalid WAN IP = {ip_info['src_ip']}")

                            if self.mode == "wtl":
                                if udp_info['payload'][0:4] == b'\xff\xff\xff\xff':
                                    print("Invalid WAN port! Aborting...")
                                    raise Exception("Invalid WAN port")
                                if self.is_valid_client_ip(ip_info['dest_ip']):
                                    if (udp_info['dest_port'] < lan_src_port_start) or (udp_info['dest_port'] >= lan_src_port_start + num_ports_per_client):
                                        raise Exception(f"Received an invalid port = {udp_info['dest_port']}")
                                    wtl_key = f"{ip_info['dest_ip']}:{udp_info['dest_port']}"
                                    if wtl_key in wan_to_lan_recv_stats:
                                        wan_to_lan_recv_stats[wtl_key] += 1
                                    else:
                                        wan_to_lan_recv_stats[wtl_key] = 1
                                    if wan_to_lan_recv_stats[wtl_key] > self.packets_per_port:
                                        raise Exception(f"Received invalid number of packets = {wtl_key}:{wan_to_lan_recv_stats[wtl_key]}")
                                else:
                                    raise Exception(f"Received an invalid LAN IP = {ip_info['dest_ip']}")
                        self.packet_count += 1

                    if ip_info['protocol'] == 6:  # TCP
                        tcp_info = self.parse_tcp_header(ip_info['payload'])
                        if tcp_info:
                            if self.mode == "ltw":
                                if tcp_info['payload'][0:4] == b'\xff\xff\xff\xff':
                                    raise Exception("Received stop signal from the NAT implementation")
                                if tcp_info['src_port'] < wan_dst_port_start:
                                    raise Exception(f"Received an invalid port = {tcp_info['src_port']}")
                                # ignore the syn packets
                                if not tcp_info['flags']['syn']:
                                    self.packet_count += 1
                                    if ip_info['src_ip'] == wan_ip:
                                        ltw_key = f"{ip_info['src_ip']}:{tcp_info['src_port']}"
                                        if ltw_key in lan_to_wan_recv_stats:
                                            lan_to_wan_recv_stats[ltw_key] += 1
                                        else:
                                            lan_to_wan_recv_stats[ltw_key] = 1
                                        if lan_to_wan_recv_stats[ltw_key] > self.packets_per_port:
                                            raise Exception(f"Received invalid number of packets = {ltw_key}:{lan_to_wan_recv_stats[ltw_key]}")
                                    else:
                                        raise Exception(f"Received an invalid WAN IP = {ip_info['src_ip']}")
                                else:
                                    if tcp_info['payload'][0:4] == b'\x12\x34\x56\x78':
                                        num_syn_pkts += 1

                            if self.mode == "wtl":
                                if tcp_info['payload'][0:4] == b'\xff\xff\xff\xff':
                                    print("Invalid WAN port! Aborting...")
                                    raise Exception("Invalid WAN port")
                                if self.is_valid_client_ip(ip_info['dest_ip']):
                                    if (tcp_info['dest_port'] < lan_src_port_start) or (tcp_info['dest_port'] >= lan_src_port_start + num_ports_per_client):
                                        raise Exception(f"Received an invalid port = {tcp_info['dest_port']}")
                                    wtl_key = f"{ip_info['dest_ip']}:{tcp_info['dest_port']}"
                                    if wtl_key in wan_to_lan_recv_stats:
                                        wan_to_lan_recv_stats[wtl_key] += 1
                                    else:
                                        wan_to_lan_recv_stats[wtl_key] = 1
                                    if wan_to_lan_recv_stats[wtl_key] > self.packets_per_port:
                                        raise Exception(f"Received invalid number of packets = {wtl_key}:{wan_to_lan_recv_stats[wtl_key]}")
                                else:
                                    raise Exception(f"Received an invalid LAN IP = {ip_info['dest_ip']}")
                                self.packet_count += 1


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
                        if self.display_packet(data, len(data)) == -1:
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

def start_test(mode, num_packets):
    try:
        receiver = PacketReceiver(mode, num_packets, iface)
        receiver.start()

        # sleep for 2 seconds before starting the sender
        time.sleep(2)
        # TODO: Take the stateful mode option from command line
        sender = PacketSender(mode, num_packets, True, iface)

        # this function starts the sender in a separate thread
        sender.start()
        sender.join()

        receiver.stop_running()
        receiver.join()
        # the receiver also verifies that the test ran successfully
        # in case of ltw or wtl modes
        receiver.cleanup()

    except KeyboardInterrupt:
        print("\nReceived interrupt signal...")
    except Exception as e:
        print(f"Unexpected error: {e}")

def verify_test(mode, num_packets):
    # Don't verify the stats in case the sender did not exit gracefully
    if not exit_sender:
        expected_table_size = num_clients * num_ports_per_client

        if mode == "ltw":
            print("LAN to WAN receiver stats check...")
            if expected_table_size != len(lan_to_wan_recv_stats):
                print(f"Receive table size incorrect. Size = {len(lan_to_wan_recv_stats)}, Expected = {expected_table_size}")
                return

            if expected_table_size != len(lan_to_wan_send_stats):
                print(f"Receive table size incorrect. Size = {len(lan_to_wan_send_stats)}, Expected = {expected_table_size}")
                return

            for key,val in lan_to_wan_recv_stats.items():
                # print(f"{key} -> {val}")
                if val != num_packets:
                    print(f"Received an invalid number of packets for {key}->{val}")
                    return

            print("SUCCESS")

        elif mode == "wtl":
            print("WAN to LAN receiver stats...")
            if expected_table_size != len(wan_to_lan_recv_stats):
                print(f"Table size incorrect. Size = {len(wan_to_lan_recv_stats)}, Expected = {expected_table_size}")
                return

            if expected_table_size != len(wan_to_lan_send_stats):
                print(f"Table size incorrect. Size = {len(wan_to_lan_send_stats)}, Expected = {expected_table_size}")
                return

            for key,val in wan_to_lan_recv_stats.items():
                # print(f"{key} -> {val}")
                if val != num_packets:
                    print(f"Received an invalid number of packets for {key}->{val}")
                    return

            print("SUCCESS")

def compare_large_dicts(dict1, dict2):
    # Quick size check first
    if len(dict1) != len(dict2):
        return False

    # Compare key by key without creating new data structures
    for key in dict1:
        if key not in dict2 or dict1[key] != dict2[key]:
            return False

    return True

def verify_both_test():
    # When we test for both LTW and WTL scenarios we verify that the
    # dictionary of received packets on the LTW interface is same
    # as the dictionary of the sent packets on the WTL interface and vice versa
    return compare_large_dicts(lan_to_wan_recv_stats, wan_to_lan_send_stats) and compare_large_dicts(wan_to_lan_recv_stats, lan_to_wan_send_stats)

def main():
    mode, num_packets = parse_arguments()

    if mode == "ltw":
        print("Mode: LAN to WAN traffic only")
    elif mode == "wtl":
        print("Mode: WAN to LAN traffic only")

    print(f"Packets per port: {num_packets}")

    if mode == "ltw" or mode == "wtl":
        start_test(mode, num_packets)
        verify_test(mode, num_packets)
    elif mode == "both":
        start_time = time.perf_counter()
        start_test("ltw", num_packets)
        if not exit_sender:
            # start the wtl test if the first one went okay
            time.sleep(30)
            start_test("wtl", num_packets)
        end_time = time.perf_counter()
        print(f"Total time = {end_time - start_time}")
        if not exit_sender:
            if num_syn_pkts != num_clients * num_ports_per_client:
                print("Failed: Syn packet mismatch")
                return
            # instead of verifying each test individually
            # we can directly compare the dictionaries to
            # verify that the test passed
            if verify_both_test():
                print("SUCCESS")
    else:
        print(f"Mode: {mode} not supported")

# TODO: End if we receive an interrupt (Ctrl + C)
# TODO: Fix the verbose mode
if __name__ == "__main__":
    main()
