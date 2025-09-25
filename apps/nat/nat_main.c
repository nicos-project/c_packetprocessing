#include <nfp.h>
#include <stdint.h>
#include <std/hash.h>
#include <nfp/me.h>
#include <nfp/mem_lkup.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <std/reg_utils.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/udp.h>

#include "config.h"

#define WAN_IP_HEX 0x36EF1C55 // 54.239.28.85
#define IP_HDR_SOURCE_OFF 12
#define IP_HDR_DESTINATION_OFF 16
#define UDP_HDR_DESTINATION_OFF 2

// LAN to WAN table
// CAM-R based lookup table with 16384 buckets
// Each bucket can store 6 src IP, UDP -> WAN port pairs
// In total we can support 98304 outgoing connections on
// the LAN interface but we are limited by the size of
// the WAN_PORT_POOL_SIZE which is ~64K ports (see below).
#define NUM_BUCKETS  (1 << 14)
#define TABLE_SZ_64    (NUM_BUCKETS * 64)
#define TBL_MEM __imem
#define DATA_OFFSET 0
#define MAX_KEYS_PER_BUCKET 6
__export TBL_MEM __align(TABLE_SZ_64)                           \
                struct mem_lkup_cam_r_48_64B_table_bucket_entry \
                nat_ltw_lkup_table[NUM_BUCKETS];
#define HASH_SEED_VALUE 0x12345678

// Avoiding the well-known ports (0-1023)
#define WAN_PORT_START 1024
// This is 64512 and is the maximum number of connections we can
// support even though we have more entries in the LAN to WAN conversion
// table
#define WAN_PORT_POOL_SIZE UINT16_MAX - WAN_PORT_START + 1

// 48 bits in total
// LAN to WAN table key
// The value is a WAN port
struct nat_ltw_lkup_key {
    union {
        struct {
            uint32_t ip_src;
            uint16_t udp_src;
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

__declspec(imem export scope(global)) struct nat_wtl_lkup_value nat_wtl_lkup_values[WAN_PORT_POOL_SIZE];

__intrinsic void add_to_table(__declspec(imem) struct mem_lkup_cam_r_48_64B_table_bucket_entry *table,
                              __declspec(cls shared) uint8_t *bucket_count, uint32_t table_idx,
                              uint64_t lkup_data, uint32_t result,
                              __declspec(ctm shared) __mem40 uint32_t *data) {
        if (bucket_count[table_idx] < MAX_KEYS_PER_BUCKET) {
            if (bucket_count[table_idx] == 0) {
                // key 0 and result 0 are in dataline1
                table[table_idx].dataline1.lookup_key_lower0 = (lkup_data & 0xffff);
                table[table_idx].dataline1.lookup_key_middle0 = ((lkup_data >> 16ull) & 0xffff);
                table[table_idx].dataline1.lookup_key_upper0 = ((lkup_data >> 32ull) & 0xffff);
                table[table_idx].dataline1.result0 = result;
            }
            else if (bucket_count[table_idx] == 1) {
                // key 1 is in dataline1 and result 1 is in dataline4
                table[table_idx].dataline1.lookup_key_lower1 = (lkup_data & 0xffff);
                table[table_idx].dataline1.lookup_key_middle1 = ((lkup_data >> 16ull) & 0xffff);
                table[table_idx].dataline1.lookup_key_upper1 = ((lkup_data >> 32ull) & 0xffff);
                table[table_idx].dataline4.result1 = result;
            }
            else if (bucket_count[table_idx] == 2) {
                // key 2 and result 2 are in dataline2
                table[table_idx].dataline2.lookup_key_lower0 = (lkup_data & 0xffff);
                table[table_idx].dataline2.lookup_key_middle0 = ((lkup_data >> 16ull) & 0xffff);
                table[table_idx].dataline2.lookup_key_upper0 = ((lkup_data >> 32ull) & 0xffff);
                table[table_idx].dataline2.result0 = result;
            }
            else if (bucket_count[table_idx] == 3) {
                // key 3 is in dataline2 and result 3 is in dataline4
                table[table_idx].dataline2.lookup_key_lower1 = (lkup_data & 0xffff);
                table[table_idx].dataline2.lookup_key_middle1 = ((lkup_data >> 16ull) & 0xffff);
                table[table_idx].dataline2.lookup_key_upper1 = ((lkup_data >> 32ull) & 0xffff);
                table[table_idx].dataline4.result3_lower = (result & 0xffff);
                table[table_idx].dataline4.result3_upper = ((result >> 16) & 0xffff);
            }
            else if (bucket_count[table_idx] == 4) {
                // key 4 and result 4 are in dataline3
                table[table_idx].dataline3.lookup_key_lower0 = (lkup_data & 0xffff);
                table[table_idx].dataline3.lookup_key_middle0 = ((lkup_data >> 16ull) & 0xffff);
                table[table_idx].dataline3.lookup_key_upper0 = ((lkup_data >> 32ull) & 0xffff);
                table[table_idx].dataline3.result0 = result;
            }
            else if (bucket_count[table_idx] == 5) {
                // key 5 is in dataline3 and result 3 is in dataline4
                table[table_idx].dataline3.lookup_key_lower1 = (lkup_data & 0xffff);
                table[table_idx].dataline3.lookup_key_middle1 = ((lkup_data >> 16ull) & 0xffff);
                table[table_idx].dataline3.lookup_key_upper1 = ((lkup_data >> 32ull) & 0xffff);
                table[table_idx].dataline4.result5 = result;
            }
            bucket_count[table_idx]++;
        }
        else {
            // If the bucket is full, we would also start getting invalid ports
            // but this serves as an explicit signal to the testing program
            // that we ran out of buckets
            *data = 0xffffffff;
        }
}

int main(void)
{
    // Just use one thread for now
    if (__ctx() == 0) {
        __gpr struct pkt_ms_info msi;
        __gpr int in_port, pkt_off;
        __gpr int i;
        __gpr uint16_t cur_wan_port = WAN_PORT_START;
        __gpr uint16_t wan_port = 0;
        __xread struct nbi_meta_catamaran nbi_meta;
        __xread struct nbi_meta_pkt_info *pi = &nbi_meta.pkt_info;
        __declspec(ctm shared) __mem40 char *pbuf;
        __declspec(ctm shared) __mem40 uint16_t *udp_src_port;
        __declspec(ctm shared) __mem40 uint32_t *ip_src_addr;
        __declspec(ctm shared) __mem40 uint16_t *udp_dst_port;
        __declspec(ctm shared) __mem40 uint32_t *ip_dst_addr;
        __declspec(ctm shared) __mem40 uint32_t *data;
        __declspec(local_mem shared) uint32_t key_hash;

        // Lookup table stuff
        __gpr uint32_t table_idx;
        __gpr uint16_t nat_wtl_lkup_idx = 0;
        __declspec(local_mem shared) struct nat_ltw_lkup_key ltw_lkup_key;
        __declspec(local_mem shared) unsigned long key_shf;
        __declspec(local_mem shared) uint64_t lkup_data_48_shf;
        __xrw uint32_t hash_lkup_key_value[2];
        __declspec(cls shared) uint8_t ltw_bucket_count[NUM_BUCKETS];

        for (i = 0; i < NUM_BUCKETS; i++) {
            ltw_bucket_count[i] = 0;
        }

        for (i = 0; i < WAN_PORT_POOL_SIZE; i++) {
            nat_wtl_lkup_values[i].word64 = 0;
        }

        key_shf = MEM_LKUP_CAM_64B_KEY_OFFSET(DATA_OFFSET, sizeof(nat_ltw_lkup_table));

        for (;;) {
            // Receive a packet
            pkt_nbi_recv(&nbi_meta, sizeof(nbi_meta));
            in_port = MAC_TO_PORT(nbi_meta.port);
            pbuf = pkt_ctm_ptr40(pi->isl, pi->pnum, 0);
            pkt_off = PKT_NBI_OFFSET;
            pkt_off += MAC_PREPEND_BYTES;

            if (in_port == 0) {
                // Port 0 is the LAN port
                // Each incoming packet on this port will be rewritten as follows:
                // 1. The source IP gets updated with the WAN IP
                // 2. The source UDP port gets updated with a free WAN port
                ip_src_addr = (__mem40 uint32_t *)(pbuf + pkt_off
                                                        + sizeof(struct eth_hdr)
                                                        + IP_HDR_SOURCE_OFF);
                udp_src_port  = (__mem40 uint16_t *)(pbuf + pkt_off
                                                          + sizeof(struct eth_hdr)
                                                          + sizeof(struct ip4_hdr));
                data = (__mem40 uint32_t *)(pbuf + pkt_off
                                                 + sizeof(struct eth_hdr)
                                                 + sizeof(struct ip4_hdr)
                                                 + sizeof(struct udp_hdr));

                ltw_lkup_key.word64 = 0;
                ltw_lkup_key.ip_src = *ip_src_addr;
                ltw_lkup_key.udp_src = *udp_src_port;

                // store a right shifted value so that we remove the 16 bits from the end and make it 48 bits
                // we basically just removed the __unused variable
                ltw_lkup_key.word64 = ltw_lkup_key.word64 >> 16ull;

                // hash the word to randomize the bucket index
                key_hash = hash_me_crc32(&ltw_lkup_key.word[1], 4, HASH_SEED_VALUE);

                ltw_lkup_key.word[1] = key_hash;

                // NAT TABLE LOOKUP OPERATIONS
                hash_lkup_key_value[0] = ltw_lkup_key.word[1];
                hash_lkup_key_value[1] = ltw_lkup_key.word[0];
                mem_lkup_cam_r_48_64B(hash_lkup_key_value, (__mem40 void *) nat_ltw_lkup_table,
                                      DATA_OFFSET, sizeof(hash_lkup_key_value),
                                      sizeof(nat_ltw_lkup_table));

                if (hash_lkup_key_value[0]) {
                    // key was found in the CAM
                    wan_port = hash_lkup_key_value[0];
                }
                else {
                    // why does it only work when we set the table_idx like this? why does lkup_key.word[0] not work?
                    table_idx = ltw_lkup_key.word[1] & (MEM_LKUP_CAM_64B_NUM_ENTRIES(sizeof(nat_ltw_lkup_table)) - 1);

                    lkup_data_48_shf = ltw_lkup_key.word64 >> (uint64_t)key_shf;
                    add_to_table(nat_ltw_lkup_table, ltw_bucket_count, table_idx, lkup_data_48_shf, cur_wan_port, data);
                    wan_port = cur_wan_port++;

                    // Update the WAN to LAN mapping too
                    nat_wtl_lkup_values[wan_port - WAN_PORT_START].dest_ip = *ip_src_addr;
                    nat_wtl_lkup_values[wan_port - WAN_PORT_START].port = *udp_src_port;
                    nat_wtl_lkup_values[wan_port - WAN_PORT_START].valid = 0x1;
                }

                // PACKET UPDATE OPERATIONS
                // The source IP address gets swapped with the WAN's IP
                *ip_src_addr = WAN_IP_HEX;
                // The source UDP port gets swapped with a WAN port which is fetched
                // from the NAT table (it either existed or a new one was created)
                *udp_src_port = wan_port;
            }
            else {
                // Port 4 is the WAN interface
                // Each incoming packet on this port will be rewritten as follows:
                // 1. The destination IP gets updated with a valid LAN client
                // 2. The destination UDP port gets updated with a valid port
                ip_dst_addr = (__mem40 uint32_t *)(pbuf + pkt_off
                                                        + sizeof(struct eth_hdr)
                                                        + IP_HDR_DESTINATION_OFF);
                udp_dst_port  = (__mem40 uint16_t *)(pbuf + pkt_off
                                                          + sizeof(struct eth_hdr)
                                                          + sizeof(struct ip4_hdr)
                                                          + UDP_HDR_DESTINATION_OFF);
                data = (__mem40 uint32_t *)(pbuf + pkt_off
                                                 + sizeof(struct eth_hdr)
                                                 + sizeof(struct ip4_hdr)
                                                 + sizeof(struct udp_hdr));
                // NAT LOOKUP OPERATIONS
                // For now, we assume that all the packets incoming on the WAN port
                // are in the range [1024, 65535]
                nat_wtl_lkup_idx = *udp_dst_port - WAN_PORT_START;
                if (nat_wtl_lkup_values[nat_wtl_lkup_idx].valid) {
                    *ip_dst_addr = nat_wtl_lkup_values[nat_wtl_lkup_idx].dest_ip;
                    *udp_dst_port = nat_wtl_lkup_values[nat_wtl_lkup_idx].port;
                }
                else {
                    // we have a problem, send a signal to the testing script
                    // that it should stop
                    *data = 0xffffffff;
                }
            }

            // Send the packet
            pkt_mac_egress_cmd_write(pbuf, pkt_off, 1, 1);
            pkt_off -= 4;
            msi = pkt_msd_write(pbuf, pkt_off);
            pkt_nbi_send(pi->isl,
                         pi->pnum,
                         &msi,
                         pi->len - MAC_PREPEND_BYTES + 4,
                         NBI,
                         PORT_TO_TMQ(in_port), // same port as what we received it on
                         nbi_meta.seqr, nbi_meta.seq, PKT_CTM_SIZE_256);
        }
    }

    return 0;
}

/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
