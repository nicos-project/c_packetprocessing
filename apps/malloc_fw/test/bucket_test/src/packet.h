#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>
#include "flow_table.h"

// TCP flags
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

// Build and send TCP packet with specified 4-tuple and flags
// lan_side: true for LAN (insert/delete), false for WAN (lookup)
int send_tcp_packet(int sockfd, int ifindex, const FiveTuple& tuple,
                    uint8_t flags, bool lan_side, uint8_t* buffer, size_t* packet_len);

// Receive TCP packet and extract response information
// Returns 0 on success with response flags and tuple filled
// Returns -1 on timeout or error
int receive_tcp_packet(int sockfd, uint8_t* buffer, size_t buffer_size,
                       uint8_t* response_flags, FiveTuple* response_tuple);

#endif // PACKET_H
