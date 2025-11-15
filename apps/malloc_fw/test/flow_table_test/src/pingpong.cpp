#include "pingpong.h"
#include "packet.h"
#include <arpa/inet.h>
#include <stdio.h>

/**
 * Ping-pong INSERT operation (LAN -> WAN)
 */
bool pingpong_insert(int sockfd, int ifindex, FlowTable& local_table,
                     const char* src_ip, uint16_t src_port,
                     const char* dst_ip, uint16_t dst_port) {
    uint8_t buffer[2048];
    size_t packet_len;

    // Create 5-tuple for LAN -> WAN
    FiveTuple tuple;
    tuple.src_ip = inet_addr(src_ip);
    tuple.src_port = src_port;
    tuple.dst_ip = inet_addr(dst_ip);
    tuple.dst_port = dst_port;
    tuple.protocol = IPPROTO_TCP;

    printf("  Sending SYN (LAN->WAN): %s\n", tuple.to_string().c_str());

    // Send SYN packet (LAN side)
    if (send_tcp_packet(sockfd, ifindex, tuple, TCP_FLAG_SYN, true, buffer, &packet_len) < 0) {
        printf("  [ERROR] Failed to send SYN packet\n");
        return false;
    }

    // Receive response
    uint8_t response_flags;
    FiveTuple response_tuple;
    if (receive_tcp_packet(sockfd, buffer, sizeof(buffer), &response_flags, &response_tuple) < 0) {
        printf("  [ERROR] Failed to receive response\n");
        return false;
    }

    printf("  Received: %s (flags: ", response_tuple.to_string().c_str());
    if (response_flags & TCP_FLAG_SYN) printf("SYN ");
    if (response_flags & TCP_FLAG_FIN) printf("FIN ");
    if (response_flags & TCP_FLAG_ACK) printf("ACK ");
    printf(")\n");

    // Check if response is FIN (insert successful)
    if (response_flags & TCP_FLAG_FIN) {
        local_table.insert(tuple);
        printf("  [SUCCESS] INSERT successful - added to local table\n");
        return true;
    } else {
        printf("  [FAIL] INSERT failed - expected FIN flag\n");
        return false;
    }
}

/**
 * Ping-pong DELETE operation (LAN -> WAN)
 */
bool pingpong_delete(int sockfd, int ifindex, FlowTable& local_table,
                     const char* src_ip, uint16_t src_port,
                     const char* dst_ip, uint16_t dst_port) {
    uint8_t buffer[2048];
    size_t packet_len;

    // Create 5-tuple for LAN -> WAN
    FiveTuple tuple;
    tuple.src_ip = inet_addr(src_ip);
    tuple.src_port = src_port;
    tuple.dst_ip = inet_addr(dst_ip);
    tuple.dst_port = dst_port;
    tuple.protocol = IPPROTO_TCP;

    printf("  Sending FIN (LAN->WAN): %s\n", tuple.to_string().c_str());

    // Send FIN packet (LAN side)
    if (send_tcp_packet(sockfd, ifindex, tuple, TCP_FLAG_FIN, true, buffer, &packet_len) < 0) {
        printf("  [ERROR] Failed to send FIN packet\n");
        return false;
    }

    // Receive response
    uint8_t response_flags;
    FiveTuple response_tuple;
    if (receive_tcp_packet(sockfd, buffer, sizeof(buffer), &response_flags, &response_tuple) < 0) {
        printf("  [ERROR] Failed to receive response\n");
        return false;
    }

    printf("  Received: %s (flags: ", response_tuple.to_string().c_str());
    if (response_flags & TCP_FLAG_SYN) printf("SYN ");
    if (response_flags & TCP_FLAG_FIN) printf("FIN ");
    if (response_flags & TCP_FLAG_ACK) printf("ACK ");
    printf(")\n");

    // Check if response is SYN (delete successful)
    if (response_flags & TCP_FLAG_SYN) {
        local_table.remove(tuple);
        printf("  [SUCCESS] DELETE successful - removed from local table\n");
        return true;
    } else {
        printf("  [FAIL] DELETE failed - expected SYN flag\n");
        return false;
    }
}

/**
 * Ping-pong LOOKUP operation (WAN -> LAN)
 */
bool pingpong_lookup(int sockfd, int ifindex, const FlowTable& local_table,
                     const char* src_ip, uint16_t src_port,
                     const char* dst_ip, uint16_t dst_port) {
    uint8_t buffer[2048];
    size_t packet_len;

    // Create 5-tuple for WAN -> LAN
    FiveTuple wan_tuple;
    wan_tuple.src_ip = inet_addr(src_ip);
    wan_tuple.src_port = src_port;
    wan_tuple.dst_ip = inet_addr(dst_ip);
    wan_tuple.dst_port = dst_port;
    wan_tuple.protocol = IPPROTO_TCP;

    // The corresponding LAN flow would be the reverse
    FiveTuple lan_tuple;
    lan_tuple.src_ip = wan_tuple.dst_ip;
    lan_tuple.src_port = wan_tuple.dst_port;
    lan_tuple.dst_ip = wan_tuple.src_ip;
    lan_tuple.dst_port = wan_tuple.src_port;
    lan_tuple.protocol = IPPROTO_TCP;

    printf("  Sending ACK (WAN->LAN): %s\n", wan_tuple.to_string().c_str());
    printf("  Looking for LAN flow: %s\n", lan_tuple.to_string().c_str());

    // Check if it exists in local table
    bool exists_locally = local_table.exists(lan_tuple);
    printf("  Exists in local table: %s\n", exists_locally ? "YES" : "NO");

    // Send ACK packet (WAN side)
    if (send_tcp_packet(sockfd, ifindex, wan_tuple, TCP_FLAG_ACK, false, buffer, &packet_len) < 0) {
        printf("  [ERROR] Failed to send ACK packet\n");
        return false;
    }

    // Receive response
    uint8_t response_flags;
    FiveTuple response_tuple;
    if (receive_tcp_packet(sockfd, buffer, sizeof(buffer), &response_flags, &response_tuple) < 0) {
        printf("  [ERROR] Failed to receive response\n");
        return false;
    }

    printf("  Received: %s (flags: ", response_tuple.to_string().c_str());
    if (response_flags & TCP_FLAG_SYN) printf("SYN ");
    if (response_flags & TCP_FLAG_FIN) printf("FIN ");
    if (response_flags & TCP_FLAG_ACK) printf("ACK ");
    printf(")\n");

    // Check if response matches our expectation
    if (response_flags & TCP_FLAG_SYN) {
        // Found in NIC table
        if (exists_locally) {
            printf("  [SUCCESS] LOOKUP matched - found in both NIC and local table\n");
            return true;
        } else {
            printf("  [FAIL] LOOKUP mismatch - NIC has it but local table doesn't (NIC BUG?)\n");
            return false;
        }
    } else if (response_flags & TCP_FLAG_FIN) {
        // Not found in NIC table
        if (!exists_locally) {
            printf("  [SUCCESS] LOOKUP matched - not found in both NIC and local table\n");
            return true;
        } else {
            printf("  [FAIL] LOOKUP mismatch - NIC doesn't have it but local table does (NIC BUG?)\n");
            return false;
        }
    } else {
        printf("  [FAIL] LOOKUP unexpected response flags\n");
        return false;
    }
}
