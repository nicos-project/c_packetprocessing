#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/udp.h>
#include <std/hash.h>
#include <nfp/me.h>
#include <nfp/mem_lkup.h>
#include <nfp/mem_bulk.h>
#include <std/reg_utils.h>

#include "config.h"
#include "pipeline.h"

#define MAC_CHAN_PER_PORT   4
#define TMQ_PER_PORT        (MAC_CHAN_PER_PORT * 8)

#define MAC_TO_PORT(x)      (x / MAC_CHAN_PER_PORT)
#define PORT_TO_TMQ(x)      (x * TMQ_PER_PORT)

#define WAN_IP_HEX 0x36EF1C55 // 54.239.28.85

// LAN to WAN table
// CAM-R based lookup table with 16384 buckets
// Each bucket can store 6 src IP, UDP -> WAN port pairs
// In total we can support 98304 outgoing connections on
// the LAN interface but we are limited by the size of
// the WAN_PORT_POOL_SIZE which is ~64K ports (see below).
#define NAT_LTW_TABLE_NUM_BUCKETS  (1 << 14)
#define TABLE_SZ_64    (NAT_LTW_TABLE_NUM_BUCKETS * 64)
#define NAT_LTW_TABLE_MEM __emem
#define DATA_OFFSET 0
#define NAT_LTW_TABLE_MAX_KEYS_PER_BUCKET 6
__export NAT_LTW_TABLE_MEM __align(TABLE_SZ_64)                   \
                struct mem_lkup_cam_r_48_64B_table_bucket_entry   \
                nat_ltw_lkup_table[NAT_LTW_TABLE_NUM_BUCKETS];
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

void semaphore_down(volatile __declspec(mem addr40) void * addr)
{
    /* semaphore "DOWN" = claim = wait */
    unsigned int addr_hi, addr_lo;
    __declspec(read_write_reg) int xfer;
    SIGNAL_PAIR my_signal_pair;

    addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)addr & 0xffffffff;

    do {
        xfer = 1;
        __asm {
            mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1], \
                sig_done[my_signal_pair];
            ctx_arb[my_signal_pair]
        }
    } while (xfer == 0);
}

void semaphore_up(volatile __declspec(mem addr40) void * addr)
{
    /* semaphore "UP" = release = signal */
    unsigned int addr_hi, addr_lo;
    __declspec(read_write_reg) int xfer;

    addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)addr & 0xffffffff;

    __asm {
        mem[incr, --, addr_hi, <<8, addr_lo, 1];
    }
}

// Global NAT state
// We need to split this between the different islands: each island serves a group of flows
// All the MEs in an island share the same lock but the NAT state is actually global
__declspec(emem export scope(island) aligned(64)) int nat_sem = 1;
__declspec(emem export scope(island)) uint16_t cur_wan_port = 0;
__declspec(emem export scope(global)) struct nat_wtl_lkup_value nat_wtl_lkup_values[WAN_PORT_POOL_SIZE];
__declspec(emem export scope(global)) uint8_t ltw_bucket_count[NAT_LTW_TABLE_NUM_BUCKETS];

__intrinsic void add_to_ltw_nat_table(uint32_t table_idx, uint64_t lkup_data, uint32_t result,
                              __declspec(ctm shared) __mem40 uint32_t *data) {
    if (ltw_bucket_count[table_idx] < NAT_LTW_TABLE_MAX_KEYS_PER_BUCKET) {
        if (ltw_bucket_count[table_idx] == 0) {
            // key 0 and result 0 are in dataline1
            nat_ltw_lkup_table[table_idx].dataline1.lookup_key_lower0 = (lkup_data & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline1.lookup_key_middle0 = ((lkup_data >> 16ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline1.lookup_key_upper0 = ((lkup_data >> 32ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline1.result0 = result;
        }
        else if (ltw_bucket_count[table_idx] == 1) {
            // key 1 is in dataline1 and result 1 is in dataline4
            nat_ltw_lkup_table[table_idx].dataline1.lookup_key_lower1 = (lkup_data & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline1.lookup_key_middle1 = ((lkup_data >> 16ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline1.lookup_key_upper1 = ((lkup_data >> 32ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline4.result1 = result;
        }
        else if (ltw_bucket_count[table_idx] == 2) {
            // key 2 and result 2 are in dataline2
            nat_ltw_lkup_table[table_idx].dataline2.lookup_key_lower0 = (lkup_data & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline2.lookup_key_middle0 = ((lkup_data >> 16ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline2.lookup_key_upper0 = ((lkup_data >> 32ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline2.result0 = result;
        }
        else if (ltw_bucket_count[table_idx] == 3) {
            // key 3 is in dataline2 and result 3 is in dataline4
            nat_ltw_lkup_table[table_idx].dataline2.lookup_key_lower1 = (lkup_data & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline2.lookup_key_middle1 = ((lkup_data >> 16ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline2.lookup_key_upper1 = ((lkup_data >> 32ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline4.result3_lower = (result & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline4.result3_upper = ((result >> 16) & 0xffff);
        }
        else if (ltw_bucket_count[table_idx] == 4) {
            // key 4 and result 4 are in dataline3
            nat_ltw_lkup_table[table_idx].dataline3.lookup_key_lower0 = (lkup_data & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline3.lookup_key_middle0 = ((lkup_data >> 16ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline3.lookup_key_upper0 = ((lkup_data >> 32ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline3.result0 = result;
        }
        else if (ltw_bucket_count[table_idx] == 5) {
            // key 5 is in dataline3 and result 3 is in dataline4
            nat_ltw_lkup_table[table_idx].dataline3.lookup_key_lower1 = (lkup_data & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline3.lookup_key_middle1 = ((lkup_data >> 16ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline3.lookup_key_upper1 = ((lkup_data >> 32ull) & 0xffff);
            nat_ltw_lkup_table[table_idx].dataline4.result5 = result;
        }
        ltw_bucket_count[table_idx]++;
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
        // Work queue stuff
        __gpr struct work_t work;
        __gpr struct pkt_ms_info msi;
        __gpr unsigned int type, island, pnum, plen, seqr, seq;
        __gpr unsigned int rnum, raddr_hi;
        __gpr uint8_t pkt_off = PKT_NBI_OFFSET + MAC_PREPEND_BYTES;
        __xread  struct work_t work_read;

        // NAT stuff
        __gpr int in_port;
        __gpr int i;
        __gpr uint16_t wan_port = 0;
        __xread struct nbi_meta_catamaran nbi_meta;
        __xread struct nbi_meta_pkt_info *pi = &nbi_meta.pkt_info;
        __declspec(ctm shared) __mem40 char *pbuf;
        __declspec(ctm shared) __mem40 struct ip4_hdr *ip_hdr;
        __declspec(ctm shared) __mem40 struct udp_hdr *udp_hdr;
        __declspec(ctm shared) __mem40 uint16_t *l4_src_port;
        __declspec(ctm shared) __mem40 uint16_t *l4_dst_port;
        __declspec(ctm shared) __mem40 uint32_t *data;

        // NAT LTW table stuff
        __gpr uint32_t table_idx;
        __gpr uint16_t nat_wtl_lkup_idx = 0;
        __declspec(local_mem shared) struct nat_ltw_lkup_key ltw_lkup_key;
        __declspec(local_mem shared) unsigned long nat_ltw_lkup_key_shf;
        __declspec(local_mem shared) uint64_t nat_ltw_lkup_data; // this is what actually goes in the CAM (right-shifted result of ltw_lkup_key.word64 by nat_ltw_lkup_key_shf)
        __xrw uint32_t nat_ltw_lkup_key_result[2];
        SIGNAL work_sig;

        island = __ISLAND;
        cur_wan_port = WAN_PORT_START + (__ISLAND - 33) * 16128; // 64512 divided by 4 worker islands, each island serves 16128 flows

        if (island == 33) {
          rnum = MEM_RING_GET_NUM(flow_ring_0);
          raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_0);
        }
        else if (island == 34) {
          rnum = MEM_RING_GET_NUM(flow_ring_1);
          raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_1);
        }
        else if (island == 35) {
          rnum = MEM_RING_GET_NUM(flow_ring_2);
          raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_2);
        }
        else if (island == 36) {
          rnum = MEM_RING_GET_NUM(flow_ring_3);
          raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_3);
        }

        for (i = 0; i < NAT_LTW_TABLE_NUM_BUCKETS; i++) {
            ltw_bucket_count[i] = 0;
        }

        for (i = 0; i < WAN_PORT_POOL_SIZE; i++) {
            nat_wtl_lkup_values[i].word64 = 0;
        }

        nat_ltw_lkup_key_shf = MEM_LKUP_CAM_64B_KEY_OFFSET(DATA_OFFSET, sizeof(nat_ltw_lkup_table));

        for (;;) {
            __mem_workq_add_thread(rnum, raddr_hi,
                            &work_read,
                            sizeof(struct work_t), sizeof(struct work_t),
                            sig_done, &work_sig);
            __wait_for_all(&work_sig);

            work = work_read;
            island = work.isl;
            pnum = work.pnum;
            plen = work.plen;
            seqr = work.seqr;
            seq = work.seq;

            pbuf = pkt_ctm_ptr40(island, pnum, 0);

            ip_hdr = (__mem40 struct ip4_hdr *)(pbuf + pkt_off + sizeof(struct eth_hdr));

            udp_hdr = (__mem40 struct udp_hdr *)(pbuf + pkt_off
                                                      + sizeof(struct eth_hdr)
                                                      + sizeof(struct ip4_hdr));

            l4_src_port  = (__mem40 uint16_t *)(&udp_hdr->sport);

            l4_dst_port  = (__mem40 uint16_t *)(&udp_hdr->dport);

            data = (__mem40 uint32_t *)(pbuf + pkt_off
                                             + sizeof(struct eth_hdr)
                                             + sizeof(struct ip4_hdr)
                                             + sizeof(struct udp_hdr));

            // Now perform a lookup in the LAN to WAN table
            ltw_lkup_key.word64 = 0;
            ltw_lkup_key.ip_src = ip_hdr->src;
            ltw_lkup_key.udp_src = *l4_src_port;

            ltw_lkup_key.word[1] = work.hash;
            nat_ltw_lkup_key_result[0] = ltw_lkup_key.word[1];
            nat_ltw_lkup_key_result[1] = ltw_lkup_key.word[0];

            semaphore_down(&nat_sem);
            // NAT TABLE LOOKUP OPERATIONS
            mem_lkup_cam_r_48_64B(nat_ltw_lkup_key_result, (__mem40 void *) nat_ltw_lkup_table,
                                  DATA_OFFSET, sizeof(nat_ltw_lkup_key_result),
                                  sizeof(nat_ltw_lkup_table));

            if (nat_ltw_lkup_key_result[0]) {
                // key was found in the CAM
                wan_port = nat_ltw_lkup_key_result[0];
            }
            else {
                table_idx = ltw_lkup_key.word[1] & (MEM_LKUP_CAM_64B_NUM_ENTRIES(sizeof(nat_ltw_lkup_table)) - 1);

                nat_ltw_lkup_data = ltw_lkup_key.word64 >> (uint64_t)nat_ltw_lkup_key_shf;
                add_to_ltw_nat_table(table_idx, nat_ltw_lkup_data, cur_wan_port, data);
                wan_port = cur_wan_port++;

                // Update the WAN to LAN mapping too
                // Each island operates on a different section of the nat_wtl_lkup_values
                // That is what having a per island lock is sufficient
                nat_wtl_lkup_values[wan_port - WAN_PORT_START].dest_ip = ip_hdr->src;
                nat_wtl_lkup_values[wan_port - WAN_PORT_START].port = *l4_src_port;
                nat_wtl_lkup_values[wan_port - WAN_PORT_START].valid = 0x1;
            }
            semaphore_up(&nat_sem);

            // PACKET UPDATE OPERATIONS
            // The source IP address gets swapped with the WAN's IP
            ip_hdr->src = WAN_IP_HEX;
            // The source UDP port gets swapped with a WAN port which is fetched
            // from the NAT table (it either existed or a new one was created)
            *l4_src_port = wan_port;

            // TODO: Add the WTL conversion too. I omitted it while copying the
            // code from the non-steering NAT since we are always just testing one
            // way LTW traffic with UDP packets and the the LTW is also the more
            // expensive case for UDP packets since this is where the write happens
            // to the CAM. The WTL case is read-only workload.

            // Send the packet back
            pkt_mac_egress_cmd_write(pbuf, pkt_off, 1, 1);
            msi = pkt_msd_write(pbuf, pkt_off - 4);
            pkt_nbi_send(island,
                         pnum,
                         &msi,
                         plen - MAC_PREPEND_BYTES + 4,
                         0, // NBI is 0
                         PORT_TO_TMQ(0), // same port as what we received it on
                         seqr, seq, PKT_CTM_SIZE_256);
        }
    }

    return 0;
}

/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
