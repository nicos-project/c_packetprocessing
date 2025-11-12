#ifndef __LB_H__
#define __LB_H__

// Load balancer configuration
#define MAX_BACKENDS 16  // Maximum number of backend servers
#define ACTIVE_BACKENDS 4  // Number of active backend servers (change as needed)

// Backend server definitions (modify these to match your setup)
// Example backend IPs: 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4
#define BACKEND_0_IP 0x0100000A  // 10.0.0.1
#define BACKEND_1_IP 0x0200000A  // 10.0.0.2
#define BACKEND_2_IP 0x0300000A  // 10.0.0.3
#define BACKEND_3_IP 0x0400000A  // 10.0.0.4

#define BACKEND_PORT 80  // Backend server port (e.g., 80 for HTTP)

// Virtual IP that clients connect to
#define VIRTUAL_IP 0x0A000001  // 1.0.0.10

// Connection tracking table configuration
#define LB_TABLE_MAX_ENTRIES_PER_BUCKET 4
#define LB_TABLE_NUM_BUCKETS 0x4000
#define LB_TABLE_ID_MASK 0x3fff

#define LB_TABLE_MEM_TYPE imem

// Load tracking metrics
// Choose one of these load metrics by uncommenting:
#define LOAD_METRIC_BYTES        1  // Track bytes forwarded
// #define LOAD_METRIC_CONNECTIONS  1  // Track number of connections
// #define LOAD_METRIC_EWMA         1  // Exponentially weighted moving average

// For EWMA: decay factor (alpha = 1/EWMA_DECAY_FACTOR)
#define EWMA_DECAY_SHIFT 3  // alpha = 1/8

// Backend server information
struct backend_info {
    uint32_t ip;           // Backend server IP
    uint16_t port;         // Backend server port
    uint8_t active;        // Is this backend active?
    uint8_t padding;
};

// Load tracking per backend
struct backend_load {
    union {
        struct {
#ifdef LOAD_METRIC_BYTES
            uint64_t total_bytes;      // Total bytes forwarded to this backend
#endif
#ifdef LOAD_METRIC_CONNECTIONS
            uint32_t active_connections;  // Number of active connections
#endif
#ifdef LOAD_METRIC_EWMA
            uint64_t ewma_load;           // EWMA of load
            uint32_t last_update_time;    // Timestamp of last update
#endif
        };
        uint64_t word64[2];
    };
};

// Connection table entry: maps client connection to backend
struct lb_table_entry {
    uint32_t four_tuple_hash;  // Hash of src_ip, dst_ip, src_port, dst_port
    uint8_t backend_id;        // Which backend server is handling this
    uint8_t valid;             // Is this entry valid?
    uint16_t padding;
};

// Connection table bucket
struct lb_table_bucket {
    uint8_t bucket_count;  // Number of entries in use
    struct lb_table_entry entry[LB_TABLE_MAX_ENTRIES_PER_BUCKET];
};

// Reverse lookup: from backend response back to client
// Key: backend_ip + backend_port + client_translated_port
struct lb_reverse_entry {
    union {
        struct {
            uint32_t client_ip;        // Original client IP
            uint16_t client_port;      // Original client port
            uint8_t backend_id;        // Which backend this is from
            uint8_t valid;             // Is this entry valid?
        };
        struct {
            uint32_t word[2];
        };
        uint64_t word64;
    };
};

// Port pool for client connections (similar to NAT)
#define CLIENT_PORT_START 10000
#define CLIENT_PORT_POOL_SIZE 55536  // 65536 - 10000

#endif /* __LB_H__ */

