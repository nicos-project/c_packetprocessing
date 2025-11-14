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
 __declspec(imem export scope(island) aligned(64)) int ct_sem = 1;
 __declspec(imem export scope(global)) uint8_t ct_bucket_count[CONN_TABLE_NUM_BUCKETS];

 int main(void)
 {
     // Just use one thread for now
    //  if (__ctx() == 0) {
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
         __gpr int i, j;
         __declspec(ctm shared) __mem40 char *pbuf;
         __declspec(ctm shared) __mem40 struct ip4_hdr *ip_hdr;
         __declspec(ctm shared) __mem40 struct udp_hdr *udp_hdr;
         __declspec(ctm shared) __mem40 uint16_t *l4_src_port;
         __declspec(ctm shared) __mem40 uint16_t *l4_dst_port;
         __declspec(ctm shared) __mem40 uint32_t *data;

         // Random access variables
         __gpr uint32_t random_value;
         __gpr uint32_t bucket_idx;
         __gpr uint32_t entry_idx;
         __gpr uint32_t accessed_value;

         // XorShift RNG state (per-context)
         __gpr uint32_t rng_state;

         island = __ISLAND;

         // Initialize RNG once per context
         rng_state = local_csr_read(local_csr_timestamp_low)
                   ^ ((__ctx() + __ME()) << 8) ^ 0x9E3779B9;

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

             udp_hdr = (__mem40 struct udp_hdr *)(pbuf + pkt_off
                                                       + sizeof(struct eth_hdr)
                                                       + sizeof(struct ip4_hdr));

             l4_src_port  = (__mem40 uint16_t *)(&udp_hdr->sport);

             l4_dst_port  = (__mem40 uint16_t *)(&udp_hdr->dport);

             data = (__mem40 uint32_t *)(pbuf + pkt_off
                                              + sizeof(struct eth_hdr)
                                              + sizeof(struct ip4_hdr)
                                              + sizeof(struct udp_hdr));


             // Random access pattern using XorShift RNG (inline)
             random_value = rng_state ? rng_state : 0x12345678;
             random_value ^= random_value << 13;
             random_value ^= random_value >> 17;
             random_value ^= random_value << 5;
             rng_state = random_value;

             // Use modulo to cover the full range of buckets
             bucket_idx = random_value % CONN_TABLE_NUM_BUCKETS;

             // Extract entry index from upper bits
             entry_idx = (random_value >> 20) & 0x3;  // Use bits [21:20] for entry (0-3)

             // Directly read the random bucket and entry
             accessed_value = conn_table[bucket_idx].four_tuple_hash_entry[entry_idx];

             // Write to packet data
             *data = accessed_value;

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
    //  }

     return 0;
 }

 /* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
