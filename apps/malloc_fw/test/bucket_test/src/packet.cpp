#include "packet.h"
#include "config.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// Build and send TCP packet
int send_tcp_packet(int sockfd, int ifindex, const FiveTuple& tuple,
                    uint8_t flags, bool lan_side, uint8_t* buffer, size_t* packet_len) {
    (void)lan_side; // Unused parameter - kept for future extensibility

    // Ethernet header
    struct ethhdr* eth = (struct ethhdr*)buffer;
    memcpy(eth->h_source, SRC_MAC, 6);
    memcpy(eth->h_dest, DST_MAC, 6);
    eth->h_proto = htons(ETH_P_IP);

    // IP header
    struct iphdr* iph = (struct iphdr*)(buffer + ETH_HLEN);
    memset(iph, 0, sizeof(struct iphdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + PAYLOAD_SIZE);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // Skip checksum
    iph->saddr = tuple.src_ip;
    iph->daddr = tuple.dst_ip;

    // TCP header
    struct tcphdr* tcph = (struct tcphdr*)(buffer + ETH_HLEN + sizeof(struct iphdr));
    memset(tcph, 0, sizeof(struct tcphdr));
    tcph->source = htons(tuple.src_port);
    tcph->dest = htons(tuple.dst_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // TCP header length (5 * 4 = 20 bytes)

    // Set flags
    tcph->fin = (flags & TCP_FLAG_FIN) ? 1 : 0;
    tcph->syn = (flags & TCP_FLAG_SYN) ? 1 : 0;
    tcph->rst = (flags & TCP_FLAG_RST) ? 1 : 0;
    tcph->psh = (flags & TCP_FLAG_PSH) ? 1 : 0;
    tcph->ack = (flags & TCP_FLAG_ACK) ? 1 : 0;
    tcph->urg = (flags & TCP_FLAG_URG) ? 1 : 0;

    tcph->window = htons(5840);
    tcph->check = 0; // Skip checksum
    tcph->urg_ptr = 0;

    // Payload - all zeros
    uint8_t* payload = buffer + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
    memset(payload, 0, PAYLOAD_SIZE);

    // Calculate total packet length
    *packet_len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr) + PAYLOAD_SIZE;

    // Send packet
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, DST_MAC, 6);

    int sent_bytes = sendto(sockfd, buffer, *packet_len, 0,
                           (struct sockaddr*)&socket_address,
                           sizeof(socket_address));

    if (sent_bytes < 0) {
        perror("sendto failed");
        return -1;
    }

    return 0;
}

// Receive TCP packet and extract response information
int receive_tcp_packet(int sockfd, uint8_t* buffer, size_t buffer_size,
                       uint8_t* response_flags, FiveTuple* response_tuple) {
    struct sockaddr_ll socket_address;
    socklen_t addr_len = sizeof(socket_address);

    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = RX_TIMEOUT_US;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt timeout");
        return -1;
    }

    while (1) {
        memset(&socket_address, 0, sizeof(socket_address));

        int recv_bytes = recvfrom(sockfd, buffer, buffer_size, 0,
                                 (struct sockaddr*)&socket_address, &addr_len);

        if (recv_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("  [TIMEOUT] No response received\n");
                return -1;
            }
            perror("recvfrom failed");
            return -1;
        }

        // Parse Ethernet header
        struct ethhdr* eth = (struct ethhdr*)buffer;

        // Check if this is an IP packet
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            continue; // Skip non-IP packets
        }

        // Parse IP header
        struct iphdr* iph = (struct iphdr*)(buffer + ETH_HLEN);

        // Check if this is TCP
        if (iph->protocol != IPPROTO_TCP) {
            continue; // Skip non-TCP packets
        }

        // Parse TCP header
        struct tcphdr* tcph = (struct tcphdr*)(buffer + ETH_HLEN + sizeof(struct iphdr));

        // Extract response information
        response_tuple->src_ip = iph->saddr;
        response_tuple->src_port = ntohs(tcph->source);
        response_tuple->dst_ip = iph->daddr;
        response_tuple->dst_port = ntohs(tcph->dest);
        response_tuple->protocol = IPPROTO_TCP;

        // Extract TCP flags
        *response_flags = 0;
        if (tcph->fin) *response_flags |= TCP_FLAG_FIN;
        if (tcph->syn) *response_flags |= TCP_FLAG_SYN;
        if (tcph->rst) *response_flags |= TCP_FLAG_RST;
        if (tcph->psh) *response_flags |= TCP_FLAG_PSH;
        if (tcph->ack) *response_flags |= TCP_FLAG_ACK;
        if (tcph->urg) *response_flags |= TCP_FLAG_URG;

        return 0; // Success
    }

    return -1;
}
