#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <std/hash.h>
#include <nfp/me.h>
#include <nfp/mem_lkup.h>
#include <nfp/mem_bulk.h>
#include <std/reg_utils.h>

#include "config.h"
#include "steer.h"
#include "nat.h"

// Global NAT state
__declspec(imem export scope(global)) struct nat_ltw_bucket nat_ltw_lkup_table[NAT_LTW_TABLE_NUM_BUCKETS];
__declspec(imem export scope(global)) uint8_t ltw_bucket_count[NAT_LTW_TABLE_NUM_BUCKETS];
__declspec(imem export scope(global)) struct nat_wtl_lkup_value nat_wtl_lkup_table[WAN_PORT_POOL_SIZE];
__declspec(imem export scope(island) aligned(64)) int nat_per_island_sem = 1;
__declspec(imem export scope(island)) uint16_t cur_wan_port = 0;

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

__intrinsic int32_t find_in_nat_ltw_table(uint32_t hash_value, uint32_t table_idx) {
    __gpr uint32_t cur_idx = 0;
    __gpr int32_t wan_port = -1;
    while (cur_idx < NAT_LTW_TABLE_MAX_ENTRIES_PER_BUCKET) {
        if (nat_ltw_lkup_table[table_idx].entry[cur_idx].four_tuple_hash == hash_value) {
            wan_port = nat_ltw_lkup_table[table_idx].entry[cur_idx].wan_port;
            break;
        }
        else if (nat_ltw_lkup_table[table_idx].entry[cur_idx].four_tuple_hash == 0) {
            // we initialize all entries to zero in the start
            // and add them sequentially, so if we found a 0 entry
            // we can break since there are no entries further down
            break;
        }
        cur_idx++;
    }
    return wan_port;
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

        // NAT stuff
        __gpr int i, j;
        __gpr uint32_t lan_or_wan;
        __gpr uint32_t hash_value;
        __gpr int32_t wan_port = -1;
        __xread struct nbi_meta_catamaran nbi_meta;
        __xread struct nbi_meta_pkt_info *pi = &nbi_meta.pkt_info;
        __declspec(ctm shared) __mem40 char *pbuf;
        __declspec(ctm shared) __mem40 struct ip4_hdr *ip_hdr;
        __declspec(ctm shared) __mem40 struct tcp_hdr *tcp_hdr;
        __declspec(ctm shared) __mem40 uint16_t *l4_src_port;
        __declspec(ctm shared) __mem40 uint16_t *l4_dst_port;
        __declspec(ctm shared) __mem40 uint32_t *data;
        __gpr uint32_t ip_src;

        // NAT LTW table stuff
        __gpr uint32_t table_idx;
        __gpr uint16_t nat_wtl_lkup_idx = 0;
        SIGNAL work_sig;

        // Initialize the LAN to WAN table
        for (i = 0; i < NAT_LTW_TABLE_NUM_BUCKETS; i++) {
            for (j = 0; j < NAT_LTW_TABLE_MAX_ENTRIES_PER_BUCKET; j++) {
                nat_ltw_lkup_table[i].entry[j].four_tuple_hash = 0;
                nat_ltw_lkup_table[i].entry[j].wan_port = 0;
            }
        }

        for (i = 0; i < WAN_PORT_POOL_SIZE; i++) {
            nat_wtl_lkup_table[i].word64 = 0;
        }

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
            ip_src = ip_hdr->src;

            if (lan_or_wan == 0) {

                hash_value = work.hash;
                table_idx = hash_value & NAT_LTW_TABLE_ID_MASK;

                if (tcp_hdr->flags & NET_TCP_FLAG_SYN) {
                    // grab a lock and add to the NAT LTW and WTL tables
                    semaphore_down(&nat_per_island_sem);

                    nat_ltw_lkup_table[table_idx].entry[ltw_bucket_count[table_idx]].four_tuple_hash = hash_value;
                    nat_ltw_lkup_table[table_idx].entry[ltw_bucket_count[table_idx]].wan_port = cur_wan_port;
                    ltw_bucket_count[table_idx]++;
                    wan_port = cur_wan_port++;

                    nat_wtl_lkup_table[wan_port - WAN_PORT_START].dest_ip = ip_hdr->src;
                    nat_wtl_lkup_table[wan_port - WAN_PORT_START].port = *l4_src_port;
                    nat_wtl_lkup_table[wan_port - WAN_PORT_START].valid = 0x1;

                    semaphore_up(&nat_per_island_sem);
                }
                else {
                    // find the wan port in the NAT table
                    // Now perform a lookup in the LAN to WAN table
                    wan_port = find_in_nat_ltw_table(hash_value, table_idx);
                    if (wan_port == -1) {
                        // This should never happen
                        *data = 0xffffff;
                    }
                }

                // PACKET UPDATE OPERATIONS
                // The source IP address gets swapped with the WAN's IP
                ip_hdr->src = WAN_IP_HEX;
                // The source UDP port gets swapped with a WAN port which is fetched
                // from the NAT table (it either existed or a new one was created)
                *l4_src_port = wan_port;
            }
            else {
                // WAN to LAN traffic
                nat_wtl_lkup_idx = *l4_dst_port - WAN_PORT_START;
                if (nat_wtl_lkup_table[nat_wtl_lkup_idx].valid) {
                    ip_hdr->dst = nat_wtl_lkup_table[nat_wtl_lkup_idx].dest_ip;
                    *l4_dst_port = nat_wtl_lkup_table[nat_wtl_lkup_idx].port;
                }
                else {
                    // we have a problem, send a signal to the testing script
                    // that it should stop
                    // *data = 0xffffffff;
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
