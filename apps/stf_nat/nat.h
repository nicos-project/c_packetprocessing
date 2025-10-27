#ifndef __NAT_H__
#define __NAT_H__
// 48 bits in total
// LAN to WAN table key
// The value is a WAN port
struct nat_ltw_lkup_key {
    union {
        struct {
            uint32_t ip_src;
            uint16_t l4_src;
            uint16_t __unused;
        };
        struct {
            uint32_t word[2];
        };
        uint64_t word64;
    };
};

// WAN to LAN key is the UDP destination port on the incoming packet on the
// WAN port. The value is an index in an array of nat_wtl_lkup_value
// structures which stores the IP and port that need to be swapped. Since we
// don't have the entries timing out, the WAN port allocation during LAN to WAN
// conversion is always sequential and we don't need a map (either a CAM based
// or SW based) for looking it up.
struct nat_wtl_lkup_value {
    union {
        struct {
            uint32_t dest_ip;
            uint16_t port;
            uint8_t valid;
        };
        struct {
            uint32_t word[2];
        };
        uint64_t word64;
    };
};

// Avoiding the well-known ports (0-1023)
#define WAN_PORT_START 1024
// This is 64512 and is the maximum number of connections we can
// support even though we have more entries in the LAN to WAN conversion
// table
#define WAN_PORT_POOL_SIZE UINT16_MAX - WAN_PORT_START + 1

#define WAN_IP_HEX 0x36EF1C55 // 54.239.28.85

#define NAT_LTW_TABLE_NUM_BUCKETS  (1 << 14)
#define TABLE_SZ_64    (NAT_LTW_TABLE_NUM_BUCKETS * 64)
#define NAT_LTW_TABLE_MEM __emem
#define DATA_OFFSET 0
#define NAT_LTW_TABLE_MAX_KEYS_PER_BUCKET 6

#endif /* __NAT_H__ */
