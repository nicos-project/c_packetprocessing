/**
 * @file: firewall.c
 * @brief: Connection table based firewall. Allows connections from the internal
 * network (LAN) and blocks unknown connections on the WAN. Simple IP source
 * based check to filter LAN and WAN traffic.
 *
 * */
#include <nfp.h>
#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_lkup.h>
#include <nfp/mem_bulk.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <std/reg_utils.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/udp.h>

#include "config.h"
#include "steer.h"

// Connection table
// Each bucket holds 4 keys. This means that we can have
// 65536 flows in total.
#define CONN_TABLE_NUM_BUCKETS (1 << 14)
#define CONN_TABLE_SZ    (CONN_TABLE_NUM_BUCKETS * 64)
#define CONN_TABLE_MAX_KEYS_PER_BUCKET 4
#define CONN_TABLE_MEM __emem
#define DATA_OFFSET 0
__export CONN_TABLE_MEM __align(CONN_TABLE_SZ)              \
          struct mem_lkup_cam128_64B_table_bucket_entry      \
          conn_table[CONN_TABLE_NUM_BUCKETS];

// 128-bit lookup key for the connection table. We would ideally use the
// 32-bit entry, 16 byte bucket CAM table but I haven't been able to make it work.
// Using the 128-bit entry, 64 byte bucket CAM table for now
struct conn_table_lkup_key {
    union {
        struct {
            uint32_t flow_hash;
            uint32_t src_ip;
            uint32_t dst_ip;
            uint32_t src_dst_udp;
        };
        struct {
            uint32_t word[4];
        };
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

// Global connection state
// We split this between the different islands: each island serves a unique set of flows due to
// the steering island assigning flows based on the four tuple hash. Each island has 8 MEs serving
// a set of flows, and more than one ME may end up serving a single flow. That is why we need an island
// scope lock on the ct_bucket_count and conn_table data structures.
__declspec(emem export scope(island) aligned(64)) int ct_sem = 1;
__declspec(emem export scope(global)) uint8_t ct_bucket_count[CONN_TABLE_NUM_BUCKETS];

__intrinsic void add_to_conn_table(uint32_t table_idx, __xwrite uint32_t *entry_data,
                                   uint32_t entry_size, __declspec(ctm shared) __mem40 uint32_t *pkt_data) {
    if (ct_bucket_count[table_idx] < CONN_TABLE_MAX_KEYS_PER_BUCKET) {
        if (ct_bucket_count[table_idx] == 0) {
            mem_write32(entry_data, (__mem40 void *) &(conn_table[table_idx].lookup_key0), entry_size);
        }
        else if (ct_bucket_count[table_idx] == 1) {
            mem_write32(entry_data, (__mem40 void *) &(conn_table[table_idx].lookup_key1), entry_size);
        }
        else if (ct_bucket_count[table_idx] == 2) {
            mem_write32(entry_data, (__mem40 void *) &(conn_table[table_idx].lookup_key2), entry_size);
        }
        else if (ct_bucket_count[table_idx] == 3) {
            mem_write32(entry_data, (__mem40 void *) &(conn_table[table_idx].lookup_key3), entry_size);
        }
        ct_bucket_count[table_idx]++;
    }
    else {
        // Send an explicit signal to the testing program
        // that we ran out of buckets
        *pkt_data = 0xffffffff;
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
        __gpr uint8_t rx_port;
        __xread  struct work_t work_read;
        SIGNAL work_sig;

        __gpr uint32_t lan_or_wan;
        __gpr int i;
        __declspec(ctm shared) __mem40 char *pbuf;
        __declspec(ctm shared) __mem40 struct ip4_hdr *ip_hdr;
        __declspec(ctm shared) __mem40 struct udp_hdr *udp_hdr;
        __declspec(ctm shared) __mem40 uint16_t *l4_src_port;
        __declspec(ctm shared) __mem40 uint16_t *l4_dst_port;
        __declspec(ctm shared) __mem40 uint32_t *data;

        // Connection table stuff
        __gpr uint32_t table_idx;
        __xwrite uint32_t conn_table_entry_data[4];
        __xrw uint32_t conn_table_lkup_data[4];
        __declspec(local_mem shared) unsigned int conn_table_lkup_key_shf;
        __declspec(local_mem shared) struct conn_table_lkup_key ct_lkup_key;

        island = __ISLAND;

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
        for (i = 0; i < CONN_TABLE_NUM_BUCKETS; i++) {
            ct_bucket_count[i] = 0;
        }

        conn_table_lkup_key_shf = MEM_LKUP_CAM_64B_KEY_OFFSET(DATA_OFFSET, sizeof(conn_table));

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
            rx_port = work.rx_port;
            lan_or_wan = work.lan_or_wan;

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

            if (lan_or_wan == 0) {
                // We start by checking if the flow is in the connection table
                // or not. We basically allow all connections on the LAN port
                for (i = 0; i < 4; i++) {
                    ct_lkup_key.word[i] = 0;
                }

                ct_lkup_key.src_ip = ip_hdr->src;
                ct_lkup_key.dst_ip = ip_hdr->dst;
                ct_lkup_key.src_dst_udp = *l4_src_port;
                ct_lkup_key.src_dst_udp = ct_lkup_key.src_dst_udp << 16;
                ct_lkup_key.src_dst_udp = ct_lkup_key.src_dst_udp | *l4_dst_port;
                ct_lkup_key.flow_hash = work.hash;

                // Perform a lookup in the connection table and see if it is there
                reg_cp(conn_table_lkup_data, ct_lkup_key.word, sizeof(ct_lkup_key.word));

                semaphore_down(&ct_sem);
                mem_lkup_cam128_64B(conn_table_lkup_data, (__mem40 void *) conn_table,
                                    DATA_OFFSET, sizeof(conn_table_lkup_data),
                                    sizeof(conn_table));

                if (conn_table_lkup_data[0]) {
                    // found
                    // maybe it is worth adding a sanity check which verifies
                    // that if the flow is present in the connection table
                    // it should also be present in the LTW NAT table
                    // *data = 0x1;
                }
                else {
                    // not found, insert it in the connection table
                    table_idx = MEM_LKUP_CAM_64B_BUCKET_IDX(ct_lkup_key.word, DATA_OFFSET, sizeof(conn_table));
                    conn_table_entry_data[0] = ((ct_lkup_key.word[1] << (32 - conn_table_lkup_key_shf)) |
                                                (ct_lkup_key.word[0] >> conn_table_lkup_key_shf));
                    conn_table_entry_data[1] = ((ct_lkup_key.word[2] << (32 - conn_table_lkup_key_shf)) |
                                                (ct_lkup_key.word[1] >> conn_table_lkup_key_shf));
                    conn_table_entry_data[2] = ((ct_lkup_key.word[3] << (32 - conn_table_lkup_key_shf)) |
                                                (ct_lkup_key.word[2] >> conn_table_lkup_key_shf));
                    conn_table_entry_data[3] = ct_lkup_key.word[3] >> conn_table_lkup_key_shf;

                    add_to_conn_table(table_idx, conn_table_entry_data,
                                      sizeof(conn_table_entry_data), data);

                    // *data = table_idx;
                    // data += 1;
                    // *data = ct_lkup_key.flow_hash;
                    // data += 1;
                    // *data = ct_lkup_key.word[0];
                }
                semaphore_up(&ct_sem);
            }
            else {
                // WAN port side. The connection should be present in the connection table or else
                // we block it
                for (i = 0; i < 4; i++) {
                    ct_lkup_key.word[i] = 0;
                }
                // Reverse the source and destination assignments
                // Since the packet is inbound to the LAN interface now
                ct_lkup_key.flow_hash = work.hash;
                ct_lkup_key.src_ip = ip_hdr->dst;
                ct_lkup_key.dst_ip = ip_hdr->src;
                ct_lkup_key.src_dst_udp = *l4_dst_port;
                ct_lkup_key.src_dst_udp = ct_lkup_key.src_dst_udp << 16;
                ct_lkup_key.src_dst_udp = ct_lkup_key.src_dst_udp | *l4_src_port;

                // Perform a lookup in the connection table and see if it is there
                reg_cp(conn_table_lkup_data, ct_lkup_key.word, sizeof(ct_lkup_key.word));
                mem_lkup_cam128_64B(conn_table_lkup_data, (__mem40 void *) conn_table,
                                    DATA_OFFSET, sizeof(conn_table_lkup_data),
                                    sizeof(conn_table));

                if (conn_table_lkup_data[0]) {
                    // *data = 0x1;
                }
                else {
                    // we have a problem, someone is trying to intrude?
                    // drop the packet
                    // *data = 0x1;
                }
            }

            // Send the packet back
            pkt_mac_egress_cmd_write(pbuf, pkt_off, 1, 1);
            msi = pkt_msd_write(pbuf, pkt_off - 4);
            pkt_nbi_send(island,
                         pnum,
                         &msi,
                         plen - MAC_PREPEND_BYTES + 4,
                         0, // NBI is 0
                         PORT_TO_TMQ(rx_port), // same port as what we received it on
                         seqr, seq, PKT_CTM_SIZE_256);
        }
    }

    return 0;
}

/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
