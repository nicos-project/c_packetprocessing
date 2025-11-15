#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

// Network interface configuration
#define INTERFACE "ens3f0np0"

// MAC addresses (modify these according to your setup)
// Source MAC (host)
static const uint8_t SRC_MAC[6] = {0x08, 0xc0, 0xeb, 0xd4, 0x4e, 0x08};
// Destination MAC (NIC)
static const uint8_t DST_MAC[6] = {0x08, 0xc0, 0xeb, 0xd4, 0x4e, 0x09};

// Default IP addresses and ports for LAN side
#define DEFAULT_LAN_SRC_IP "192.168.1.1"
#define DEFAULT_LAN_SRC_PORT 49000
#define DEFAULT_LAN_DST_IP "12.11.10.9"
#define DEFAULT_LAN_DST_PORT 80

// TCP payload size
#define PAYLOAD_SIZE 18

// Receive timeout in microseconds
#define RX_TIMEOUT_US 1000

#endif // CONFIG_H
