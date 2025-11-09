#ifndef __NAT_H__
#define __NAT_H__

// Avoiding the well-known ports (0-1023)
#define WAN_PORT_START 1024
// This is 64512 and is the maximum number of connections we can
// support even though we have more entries in the LAN to WAN conversion
// table
#define WAN_PORT_POOL_SIZE UINT16_MAX - WAN_PORT_START + 1

#define WAN_IP_HEX 0x36EF1C55 // 54.239.28.85

#define NAT_LTW_TABLE_MAX_ENTRIES_PER_BUCKET 4
#define NAT_LTW_TABLE_NUM_BUCKETS 0x4000
#define NAT_LTW_TABLE_ID_MASK 0x3fff

struct nat_ltw_bucket_entry {
    uint32_t four_tuple_hash;
    uint16_t wan_port;
};

struct nat_ltw_bucket {
    struct nat_ltw_bucket_entry entry[NAT_LTW_TABLE_MAX_ENTRIES_PER_BUCKET];
};

// WAN to LAN key is the UDP destination port on the incoming packet on the
// WAN port. The value is an index in an array of nat_wtl_lkup_value
// structures which stores the IP and port that need to be swapped.
// Change the name to something else for this
struct nat_wtl_lkup_value {
    union {
        struct {
            uint32_t dest_ip;
            uint16_t port;
            // Why do we need the valid parameter?
            uint8_t valid;
        };
        struct {
            uint32_t word[2];
        };
        uint64_t word64;
    };
};

#endif /* __NAT_H__ */
