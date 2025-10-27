#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <std/hash.h>
#include <nfp/me.h>
#include <nfp/mem_lkup.h>
#include <nfp/mem_bulk.h>
#include <std/reg_utils.h>

#include "config.h"
#include "steer.h"
#include "nat.h"

__import NAT_LTW_TABLE_MEM struct mem_lkup_cam_r_48_64B_table_bucket_entry nat_ltw_lkup_table[NAT_LTW_TABLE_NUM_BUCKETS];
__import __emem struct nat_wtl_lkup_value nat_wtl_lkup_table[WAN_PORT_POOL_SIZE];

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
        __gpr int i;
        __gpr uint16_t wan_port = 0;
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
        __declspec(local_mem shared) struct nat_ltw_lkup_key ltw_lkup_key;
        __declspec(local_mem shared) unsigned long nat_ltw_lkup_key_shf;
        __declspec(local_mem shared) uint64_t nat_ltw_lkup_data; // this is what actually goes in the CAM (right-shifted result of ltw_lkup_key.word64 by nat_ltw_lkup_key_shf)
        __xrw uint32_t nat_ltw_lkup_key_result[2];
        SIGNAL work_sig;

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

            // Assume for now that the LAN IPs are in range 192.168.1.0/24
            // Alternatively, we could also check the destination IP and see if it matches the WAN IP
            // to make this decision
            ip_src = ip_src >> 8; // TODO: it should be right shifted by 32 - prefix length

            // TODO: Move this if condition to the steering core and see how it affects performance
            if (!(ip_src ^ 0x00C0A801)) {
                // Now perform a lookup in the LAN to WAN table
                ltw_lkup_key.word64 = 0;
                ltw_lkup_key.ip_src = ip_hdr->src;
                ltw_lkup_key.l4_src = *l4_src_port;

                ltw_lkup_key.word[1] = work.hash;
                nat_ltw_lkup_key_result[0] = ltw_lkup_key.word[1];
                nat_ltw_lkup_key_result[1] = ltw_lkup_key.word[0];

                // NAT TABLE LOOKUP OPERATIONS
                mem_lkup_cam_r_48_64B(nat_ltw_lkup_key_result, (__mem40 void *) nat_ltw_lkup_table,
                                      DATA_OFFSET, sizeof(nat_ltw_lkup_key_result),
                                      sizeof(nat_ltw_lkup_table));

                if (nat_ltw_lkup_key_result[0]) {
                    // key was found in the CAM
                    wan_port = nat_ltw_lkup_key_result[0];
                }
                else {
                    // This should never happen
                    *data = 0xffffff;
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
