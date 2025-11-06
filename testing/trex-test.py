from trex_stl_lib.api import *
import scapy.all
import os
import sys
import time
import math
import numpy as np

def start_trex_server(trex_path="/path/to/trex"):
    """Start TRex server in the background"""
    try:
        # Kill any existing TRex processes
        os.system("sudo pkill -9 t-rex-64")
        time.sleep(2)

        # Start TRex server
        cmd = f"cd {trex_path} && sudo ./t-rex-64 -i -c 8 --no-scapy-server"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Wait for TRex to initialize
        print("Starting TRex server...")
        time.sleep(10)

        # Verify TRex is running
        result = os.system("pgrep t-rex-64 > /dev/null")
        if result == 0:
            print("TRex server started successfully")
            return process
        else:
            print("Failed to start TRex server")
            sys.exit(1)
    except Exception as e:
        print(f"Error starting TRex: {e}")
        sys.exit(1)

def stop_trex_server(process):
    """Stop the TRex server"""
    try:
        print("Stopping TRex server...")
        # Try graceful termination first
        process.terminate()
        time.sleep(2)

        print("TRex server stopped")
    except Exception as e:
        print(f"Error stopping TRex: {e}")
        # Force kill as fallback
        os.system("sudo pkill -9 t-rex-64")

def create_udp_stream_with_var_sport(pkt_size, src_ip, dst_ip, base_sport, num_flows, dst_port=80):
    """
    Create a single stream that varies source port across num_flows.
    This avoids creating separate streams for each flow.
    """
    crc_len = 4
    pkt = Ether(src="00:15:4d:13:3b:34", dst="e8:eb:d3:f7:6c:26") / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(dport=dst_port, sport=base_sport)
    num_data_bytes = pkt_size - len(pkt) - crc_len
    pkt = pkt / Raw(b"\x00" * num_data_bytes)

    # Field engine to vary source port
    vm = STLScVmRaw([
        STLVmFlowVar("src_port",
                     min_value=base_sport,
                     max_value=base_sport + num_flows - 1,
                     size=2,
                     op="inc"),
        STLVmWrFlowVar(fv_name="src_port", pkt_offset="UDP.sport"),
        STLVmFixChecksumHw(l3_offset="IP", l4_offset="UDP", l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)
    ])

    return STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont())

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

        udp_stream = create_udp_stream_with_var_sport(
            pkt_size,
            "192.168.1.1",
            "12.11.10.9",
            0,  # base source port
            num_flows,
            80     # destination port
        )

        c.add_streams([udp_stream], ports = [0])

        c.clear_stats()

        c.start(ports = [0], mult = rate, duration = 60)

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

def start_tpt_exp(nw_func, num_runs):
    pkt_sizes = [64, 128, 256, 512, 1024, 1518]
    num_flows = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
    pkt_sizes = [64]
    num_flows = [1, 128]
    tx_retry_count = 0
    for flow_count in num_flows:
        for pkt_size in pkt_sizes:
            tpts_achieved = []
            i = 0
            while i < num_runs:
                # Start TRex server before this
                proc = start_trex_server("/opt/trex/v3.06")
                print(f"Testing with packet size: {pkt_size}")
                exit_code = os.system(f'cd ~/nic-os/c_packetprocessing/apps/packet_steer/ && ./build_and_load.sh {nw_func}')
                if exit_code != 0:
                    sys.exit(1)
                # Wait for the link to come up
                time.sleep(10)
                max_load = 40_000_000_000
                rate = convert_rate_to_trex_mult(max_load)
                stats = start_stl_test(pkt_size, rate, flow_count, False)
                port_0_stats = stats.get(0, {})
                print(port_0_stats)
                trex_tx_pps = port_0_stats.get("tx_pps", 0)
                # We have observed that sometimes, TRex is unable to send
                # packets at line rate. This has been observed with only min sized packets
                # for now and the fix can either be to simply restart the test, restart
                # the TRex server or reboot the machine completely. The root cause of
                # the issue is unknown.
                pkt_size_l1_bits = (pkt_size + 20) * 8 # 20 bytes ethernet L1 header + trailer
                theoretical_pps_l1 = max_load / pkt_size_l1_bits
                # To compare, I don't want to be super precise. Just want to make sure
                # that the packet rate TRex sent at is the same as what we expect
                # rounded down to the nearest integer in Mpps. For instance, the theoretical
                # packet rate for min sized packets is 59.523 Mpps. We might get 59.1
                # or 59.2 from TRex which is reasonably close for our purpose. So we just
                # care that the two numbers round down to 59 Mpps
                trex_tx_mpps = math.floor(trex_tx_pps / 1_000_000)
                theoretical_tx_mpps = math.floor(theoretical_pps_l1 / 1_000_000)
                if trex_tx_mpps < theoretical_tx_mpps:
                    print("Test failed because TRex couldn't reach line rate Tx")
                    tx_retry_count += 1
                    if tx_retry_count == 3:
                        print("TRex failed 3 times consecutively. Rebooting the machine may help. Exiting...")
                        sys.exit(1)
                    else:
                        print("Restarting the test...")
                else:
                    # Things went fine, record the throughput
                    tx_retry_count = 0 # reset the count
                    rx_pps = port_0_stats.get("rx_pps", 0)
                    rx_gbps = (rx_pps * pkt_size_l1_bits) / 1_000_000_000
                    tpts_achieved.append(rx_gbps)
                    # only increment if the test passed otherwise the size
                    # of tpts_achieved will be less than the number of runs
                    i += 1

                stop_trex_server(proc)

            data_array = np.array(tpts_achieved)
            mean_value = np.mean(data_array)
            median_value = np.median(data_array)
            std_dev_value = np.std(data_array)

            filename = f"{nw_func}_tpt.csv"
            if os.path.exists(filename):
                with open(filename, "a") as stats_file:
                    stats_file.write(f"{pkt_size},{flow_count},{mean_value},{median_value},{std_dev_value}\n")
            else:
                with open(filename, "a") as stats_file:
                    stats_file.write(f"pkt_size,flow_count,mean,median,std_dev\n")
                    stats_file.write(f"{pkt_size},{flow_count},{mean_value},{median_value},{std_dev_value}\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 trex-test.py <mode> [num_runs]")
        print("Mode: nat or firewall or echo. Must mention one mode.")
        print("Num runs: Number of times to run the test. Default is 1.")
        sys.exit(1)

    nw_func = sys.argv[1]
    if nw_func != "nat" and nw_func != "firewall" and nw_func != "echo":
        print("Usage: python3 trex-test.py <mode> [num_runs]")
        print("Mode: nat or firewall. Must mention one mode.")
        print("Num runs: Number of times to run the test. Default is 1.")
        sys.exit(1)

    num_runs = 1
    if len(sys.argv) == 3:
        num_runs = int(sys.argv[2])

    start_tpt_exp(nw_func, num_runs)
    print("Run `stty sane` to get your terminal back. TODO (kshitij): Fix this")

if __name__ == "__main__":
    main()
