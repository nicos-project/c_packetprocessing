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

// LAN to WAN table
// CAM-R based lookup table with 16384 buckets
// Each bucket can store 6 src IP, UDP -> WAN port pairs
// In total we can support 98304 outgoing connections on
// the LAN interface but we are limited by the size of
// the WAN_PORT_POOL_SIZE which is ~64K ports (see below).
__export NAT_LTW_TABLE_MEM __align(TABLE_SZ_64)                   \
                struct mem_lkup_cam_r_48_64B_table_bucket_entry   \
                nat_ltw_lkup_table[NAT_LTW_TABLE_NUM_BUCKETS];

// Global NAT state
__declspec(emem export scope(island)) uint16_t cur_wan_port = 0;
__declspec(emem export scope(global)) struct nat_wtl_lkup_value nat_wtl_lkup_table[WAN_PORT_POOL_SIZE];
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
        cur_wan_port = WAN_PORT_START;

        rnum = MEM_RING_GET_NUM(syn_ring);
        raddr_hi = MEM_RING_GET_MEMADDR(syn_ring);

        for (i = 0; i < NAT_LTW_TABLE_NUM_BUCKETS; i++) {
            ltw_bucket_count[i] = 0;
        }

        for (i = 0; i < WAN_PORT_POOL_SIZE; i++) {
            nat_wtl_lkup_table[i].word64 = 0;
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

            // TODO: Maybe add support for UDP as well?
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
                // Since this is a SYN packet, the flow should not be present in the NAT table
                // Add it
                ltw_lkup_key.word64 = 0;
                ltw_lkup_key.ip_src = ip_hdr->src;
                ltw_lkup_key.l4_src = *l4_src_port;

                ltw_lkup_key.word[1] = work.hash;
                nat_ltw_lkup_key_result[0] = ltw_lkup_key.word[1];
                nat_ltw_lkup_key_result[1] = ltw_lkup_key.word[0];

                // NAT TABLE LOOKUP OPERATIONS
                /*mem_lkup_cam_r_48_64B(nat_ltw_lkup_key_result, (__mem40 void *) nat_ltw_lkup_table,
                                      DATA_OFFSET, sizeof(nat_ltw_lkup_key_result),
                                      sizeof(nat_ltw_lkup_table));

                if (nat_ltw_lkup_key_result[0]) {
                    // key was found in the CAM
                    // This case shouldn't happen at all!
                }
                else {*/
                    table_idx = ltw_lkup_key.word[1] & (MEM_LKUP_CAM_64B_NUM_ENTRIES(sizeof(nat_ltw_lkup_table)) - 1);

                    nat_ltw_lkup_data = ltw_lkup_key.word64 >> (uint64_t)nat_ltw_lkup_key_shf;
                    add_to_ltw_nat_table(table_idx, nat_ltw_lkup_data, cur_wan_port, data);
                    wan_port = cur_wan_port++;

                    // Update the WAN to LAN mapping too
                    // Each island operates on a different section of the nat_wtl_lkup_table
                    // That is what having a per island lock is sufficient
                    nat_wtl_lkup_table[wan_port - WAN_PORT_START].dest_ip = ip_hdr->src;
                    nat_wtl_lkup_table[wan_port - WAN_PORT_START].port = *l4_src_port;
                    nat_wtl_lkup_table[wan_port - WAN_PORT_START].valid = 0x1;
                // }

                // PACKET UPDATE OPERATIONS
                // The source IP address gets swapped with the WAN's IP
                ip_hdr->src = WAN_IP_HEX;
                // The source UDP port gets swapped with a WAN port which is fetched
                // from the NAT table (it either existed or a new one was created)
                *l4_src_port = wan_port;
            }
            else {
                // SYN worker only handles packets on the LAN interface
                // Do we need it here too?
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
