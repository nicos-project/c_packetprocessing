#ifndef PINGPONG_H
#define PINGPONG_H

#include <stdint.h>
#include "flow_table.h"

/**
 * Ping-pong INSERT operation (LAN -> WAN)
 *
 * Sends a SYN packet from LAN to WAN
 * Direction: LAN -> WAN (lan_or_wan = 0, allows INSERT)
 * Example: 192.168.1.1:49000 -> 12.11.10.9:80
 * Expects FIN response indicating successful insert
 * Adds flow to local table if successful
 *
 * @param sockfd Socket file descriptor
 * @param ifindex Interface index
 * @param local_table Reference to local flow table
 * @param src_ip Source IP address (LAN side, e.g., 192.168.1.1)
 * @param src_port Source port (LAN side)
 * @param dst_ip Destination IP address (WAN side, e.g., 12.11.10.9)
 * @param dst_port Destination port (WAN side)
 * @return true if insert successful (FIN received), false otherwise
 */
bool pingpong_insert(int sockfd, int ifindex, FlowTable& local_table,
                     const char* src_ip, uint16_t src_port,
                     const char* dst_ip, uint16_t dst_port);

/**
 * Ping-pong DELETE operation (LAN -> WAN)
 *
 * Sends a FIN packet from LAN to WAN
 * Direction: LAN -> WAN (lan_or_wan = 0, allows DELETE)
 * Example: 192.168.1.1:49000 -> 12.11.10.9:80
 * Expects SYN response indicating successful delete
 * Removes flow from local table if successful
 *
 * @param sockfd Socket file descriptor
 * @param ifindex Interface index
 * @param local_table Reference to local flow table
 * @param src_ip Source IP address (LAN side, e.g., 192.168.1.1)
 * @param src_port Source port (LAN side)
 * @param dst_ip Destination IP address (WAN side, e.g., 12.11.10.9)
 * @param dst_port Destination port (WAN side)
 * @return true if delete successful (SYN received), false otherwise
 */
bool pingpong_delete(int sockfd, int ifindex, FlowTable& local_table,
                     const char* src_ip, uint16_t src_port,
                     const char* dst_ip, uint16_t dst_port);

/**
 * Ping-pong LOOKUP operation (WAN -> LAN)
 *
 * Sends a plain TCP packet (ACK flag) from WAN to LAN
 * Direction: WAN -> LAN (lan_or_wan = 1, only allows LOOKUP)
 * Example: 12.11.10.9:80 -> 192.168.1.1:49000
 * Expects SYN if found, FIN if not found
 * Compares NIC result with local table to verify consistency
 *
 * @param sockfd Socket file descriptor
 * @param ifindex Interface index
 * @param local_table Reference to local flow table
 * @param src_ip Source IP address (WAN side, e.g., 12.11.10.9)
 * @param src_port Source port (WAN side)
 * @param dst_ip Destination IP address (LAN side, e.g., 192.168.1.1)
 * @param dst_port Destination port (LAN side)
 * @return true if NIC and local table match, false if mismatch (indicates NIC bug)
 */
bool pingpong_lookup(int sockfd, int ifindex, const FlowTable& local_table,
                     const char* src_ip, uint16_t src_port,
                     const char* dst_ip, uint16_t dst_port);

#endif // PINGPONG_H
