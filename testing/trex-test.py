from trex_stl_lib.api import *
import scapy.all
import os
import sys
import time

def create_udp_stream(pkt_size, src_ip, dst_ip, src_port, dst_port):
    crc_len = 4
    pkt = Ether(src="00:15:4d:13:3b:34", dst="e8:eb:d3:f7:6c:26") / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(dport=dst_port, sport=src_port)
    num_data_bytes = pkt_size - len(pkt) - crc_len
    pkt = pkt / Raw(b"\x00" * num_data_bytes)

    return STLStream(packet = STLPktBuilder(pkt = pkt), mode = STLTXCont())

def start_stl_test(pkt_size, rate, num_flows, validate = True):
    try:
        c = STLClient()

        c.connect()

        c.reset(ports = [0, 1])

        udp_streams = []
        flow_idx = 0

        for i in range(num_flows):
            udp_stream = create_udp_stream(pkt_size, "192.168.1.1", "12.11.10.9", 49000 + flow_idx, 80)
            udp_streams.append(udp_stream)
            flow_idx += 1

        c.add_streams(udp_streams, ports = [0])

        c.clear_stats()

        c.start(ports = [0], mult = rate, duration = 10)

        c.wait_on_traffic(ports = [0])

        stats = c.get_stats()
        if not validate:
            return stats

        port_0_stats = stats.get(0, {})
        opackets = port_0_stats.get("opackets", 0)
        ipackets = port_0_stats.get("ipackets", 0)

        if opackets != ipackets:
            print ("Stats verification failed:")
            print (port_0_stats)
            return False

        return True

    finally:
        c.disconnect()

def convert_rate_to_trex_mult(load_bps):
    """
    Convert a load value in bits per second to TRex multiplier format.

    Args:
        load_bps: Load in bits per second (int or float)

    Returns:
        str: TRex rate string (e.g., "10gbpsl1", "500mbpsl1", "50kbpsl1")
    """
    # Define conversion thresholds
    GBPS = 1_000_000_000
    MBPS = 1_000_000
    KBPS = 1_000

    # Convert to appropriate unit
    if load_bps >= GBPS:
        value = load_bps / GBPS
        unit = "gbps"
    elif load_bps >= MBPS:
        value = load_bps / MBPS
        unit = "mbps"
    elif load_bps >= KBPS:
        value = load_bps / KBPS
        unit = "kbps"
    else:
        value = load_bps
        unit = "bps"

    # Format the value (round to 2 decimal places)
    if value == int(value):
        formatted_value = str(int(value))
    else:
        formatted_value = f"{value:.2f}".rstrip('0').rstrip('.')

    return f"{formatted_value}{unit}l1"

def start_zero_loss_tpt_exp():
    pkt_sizes = [64, 128, 256, 512, 1024, 1518]
    # We want to perform a binary search to figure out the zero loss throughput
    # We start with a certain value (right now it is 10G, but it can depend based on the packet size.
    # Smaller packet sizes may take longer to converge with higher start rates
    for pkt_size in pkt_sizes:
        print(f"Testing with packet size: {pkt_size}")
        # Try with max load once, if it works, don't run binary search
        # all rates in bps
        start_rate = 0
        end_rate = 40_000_000_000
        rate = convert_rate_to_trex_mult(end_rate)
        print(rate)
        if not start_stl_test(pkt_size, rate, 1):
            # print("Starting binary search")
            while start_rate < end_rate:
                cur_load = round((start_rate + end_rate) / 2, 2)
                rate = convert_rate_to_trex_mult(cur_load)
                # print(f"============ Trying with rate: {rate} ===========")
                if not start_stl_test(pkt_size, rate, 1):
                    # DUT cannot keep up
                    # Reduce the window with end at the current load
                    # Adjust by 1 Mbps
                    end_rate = cur_load - 1_000_000
                else:
                    # DUT can keep up
                    # Reduce the window with start at the current load
                    # Adjust by 1 Mbps
                    start_rate = cur_load + 1_000_000
        with open(f"nat_zero_loss_tpt.csv", "a") as stats_file:
            stats_file.write(f"{pkt_size},{rate}\n")

def start_tpt_exp():
    pkt_sizes = [64, 128, 256, 512, 1024, 1518]
    num_flows = [1, 2, 3, 4]
    for flow_count in num_flows:
        for pkt_size in pkt_sizes:
            print(f"Testing with packet size: {pkt_size}")
            exit_code = os.system('cd /home/kshitij/nic-os/c_packetprocessing/apps/packet_steer/ && ./build_and_load.sh nat')
            if exit_code != 0:
                sys.exit(1)
            # Wait for the link to come up
            time.sleep(10)
            max_load = 40_000_000_000
            rate = convert_rate_to_trex_mult(max_load)
            stats = start_stl_test(pkt_size, rate, flow_count, False)
            port_0_stats = stats.get(0, {})
            rx_pps = port_0_stats.get("rx_pps", 0)
            with open(f"nat_tpt.csv", "a") as stats_file:
                stats_file.write(f"{pkt_size},{flow_count},{rx_pps}\n")

def main():
    if len(sys.argv) != 1:
        print("Usage: python3 trex-test.py")
        sys.exit(1)
    start_tpt_exp()

if __name__ == "__main__":
    main()
