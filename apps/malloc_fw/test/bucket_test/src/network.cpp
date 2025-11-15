#include "network.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

// Get interface index by name
int get_interface_index(int sockfd, const char* ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        return -1;
    }

    return ifr.ifr_ifindex;
}

// Create and configure raw packet socket
int create_raw_socket(const char* ifname, int* ifindex) {
    // Create raw socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket creation failed (need root privileges)");
        return -1;
    }

    // Get interface index
    *ifindex = get_interface_index(sockfd, ifname);
    if (*ifindex < 0) {
        close(sockfd);
        return -1;
    }

    printf("Interface %s index: %d\n", ifname, *ifindex);
    return sockfd;
}

// Set interface to promiscuous mode
int set_promiscuous_mode(int sockfd, int ifindex) {
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifindex;
    mr.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        perror("setsockopt PACKET_MR_PROMISC");
        return -1;
    }

    printf("Interface set to promiscuous mode\n");
    return 0;
}

// Bind socket to specific interface
int bind_to_interface(int sockfd, int ifindex) {
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind to interface failed");
        return -1;
    }

    return 0;
}
