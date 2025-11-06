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
#include <net/tcp.h>

#include "config.h"
#include "steer.h"

#define CONN_TABLE_NUM_BUCKETS 16384
#define CONN_TABLE_MAX_KEYS_PER_BUCKET 4
struct conn_table_bucket {
    // Each bucket basically holds four keys
    uint32_t four_tuple_hash_entry[CONN_TABLE_MAX_KEYS_PER_BUCKET];
};

// Will aligning this help?
__declspec(imem export scope(global)) struct conn_table_bucket conn_table[CONN_TABLE_NUM_BUCKETS];

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
// Each bucket has its own lock in imem for fine-grained concurrency control.
__declspec(imem export scope(island)) int ct_sem[CONN_TABLE_NUM_BUCKETS];
__declspec(imem export scope(global)) uint8_t ct_bucket_count[CONN_TABLE_NUM_BUCKETS];

__intrinsic uint8_t find_in_conn_table(uint32_t hash_value, uint32_t table_idx) {
    __gpr uint32_t cur_idx = 0;
    __gpr uint8_t present_in_conn_table = 0;
    while (cur_idx < CONN_TABLE_MAX_KEYS_PER_BUCKET) {
        if (conn_table[table_idx].four_tuple_hash_entry[cur_idx] == hash_value) {
            present_in_conn_table = 1;
            break;
        }
        else if (conn_table[table_idx].four_tuple_hash_entry[cur_idx] == 0) {
            // we initialize all entries to zero in the start
            // and add them sequentially, so if we found a 0 entry
            // we can break since there are no entries further down
            break;
        }
        cur_idx++;
    }
    return present_in_conn_table;
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
        __gpr uint32_t hash_value;
        __gpr int i, j;
        __gpr uint32_t ip_tmp;
        __gpr uint16_t port_tmp;
        __declspec(ctm shared) __mem40 char *pbuf;
        __declspec(ctm shared) __mem40 struct ip4_hdr *ip_hdr;
        __declspec(ctm shared) __mem40 struct tcp_hdr *tcp_hdr;
        __declspec(ctm shared) __mem40 uint16_t *l4_src_port;
        __declspec(ctm shared) __mem40 uint16_t *l4_dst_port;
        __declspec(ctm shared) __mem40 uint32_t *data;

        // Connection table stuff
        __gpr uint32_t table_idx;
        __gpr uint8_t present_in_conn_table;

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

        // Ideally this init should be done by just one ME out of all the MEs
        for (i = 0; i < CONN_TABLE_NUM_BUCKETS; i++) {
            ct_sem[i] = 1;  // Initialize each bucket's lock
            for (j = 0; j < CONN_TABLE_MAX_KEYS_PER_BUCKET; j++) {
                conn_table[i].four_tuple_hash_entry[j] = 0;
            }
        }

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

            tcp_hdr = (__mem40 struct tcp_hdr *)(pbuf + pkt_off
                                                      + sizeof(struct eth_hdr)
                                                      + sizeof(struct ip4_hdr));

            l4_src_port  = (__mem40 uint16_t *)(&tcp_hdr->sport);

            l4_dst_port  = (__mem40 uint16_t *)(&tcp_hdr->dport);

            data = (__mem40 uint32_t *)(pbuf + pkt_off
                                             + sizeof(struct eth_hdr)
                                             + sizeof(struct ip4_hdr)
                                             + sizeof(struct tcp_hdr));


            if (lan_or_wan == 0) {
                // We start by checking if the flow is in the connection table
                // or not. We basically allow all connections on the LAN port
                //
                // Perform a lookup in the connection table and see if it is there
                hash_value = work.hash;
                table_idx = hash_value & 0x3fff;

                semaphore_down(&ct_sem[table_idx]);
                present_in_conn_table = find_in_conn_table(hash_value, table_idx);
                if (!present_in_conn_table) {
                    // not found, insert it in the connection table
                    if (ct_bucket_count[table_idx] < CONN_TABLE_MAX_KEYS_PER_BUCKET) {
                        conn_table[table_idx].four_tuple_hash_entry[ct_bucket_count[table_idx]] = hash_value;
                        ct_bucket_count[table_idx]++;
                        // Uncomment to test with firewall-test.py
                        // *data = 0x12345678;
                    }
                    // else {
                        // Send an explicit signal to the testing program
                        // that we ran out of keys in the bucket
                        // Uncomment to test with firewall-test.py
                        // *data = 0xffffffff;
                    // }
                }
                else {
                }
                semaphore_up(&ct_sem[table_idx]);
            }
            else {
                // WAN port side. The connection should be present in the connection table or else
                // we block it
                hash_value = work.hash;
                table_idx = hash_value & 0x3fff;

                present_in_conn_table = find_in_conn_table(hash_value, table_idx);

                if (present_in_conn_table) {
                    // found
                    // we only do useful stuff on the WAN port side with this
                    // *data = hash_value;
                    // *data = 0x2;
                    // Uncomment to test with firewall-test.py
                    // *data = 0xabcdef12;
                }
                // else {
                    // we have a problem, someone is trying to intrude?
                    // drop the packet
                    // Uncomment to test with firewall-test.py
                    // *data = 0xffffffff;
                    // data += 1;
                    // *data = hash_value;
                // }
            }

            // Swap IP addresses
            ip_tmp = ip_hdr->src;
            ip_hdr->src = ip_hdr->dst;
            ip_hdr->dst = ip_tmp;

            // Swap ports
            port_tmp = *l4_src_port;
            *l4_src_port = *l4_dst_port;
            *l4_dst_port = port_tmp;

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
