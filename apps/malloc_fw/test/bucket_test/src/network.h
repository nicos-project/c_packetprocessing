#ifndef NETWORK_H
#define NETWORK_H

// Get interface index by name
int get_interface_index(int sockfd, const char* ifname);

// Create and configure raw packet socket
int create_raw_socket(const char* ifname, int* ifindex);

// Set interface to promiscuous mode
int set_promiscuous_mode(int sockfd, int ifindex);

// Bind socket to specific interface
int bind_to_interface(int sockfd, int ifindex);

#endif // NETWORK_H
