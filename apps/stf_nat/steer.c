#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <std/hash.h>

#include "config.h"
#include "steer.h"

#define HASH_SEED_VALUE 0x12345678

struct flow_four_tuple {
    union {
        struct {
            uint32_t ip_src;
            uint32_t ip_dst;
            uint16_t l4_src;
            uint16_t l4_dst;
        };
        uint64_t word64[2];
    };
};

int main() {
  __gpr struct work_t work;
  __gpr uint32_t seq, seqr;
  __gpr unsigned int rnum, raddr_hi;
  __gpr uint8_t pkt_off = PKT_NBI_OFFSET + MAC_PREPEND_BYTES;
  __gpr uint8_t flow_island = 0;
  __gpr uint32_t flow_hash;
  __gpr struct flow_four_tuple flow_4_tuple;
  __xwrite struct work_t work_xfer;
  __xread struct nbi_meta_catamaran nbi_meta;
  __xread struct nbi_meta_pkt_info *pi = &nbi_meta.pkt_info;
  __declspec(ctm) __mem40 struct ip4_hdr *ip_hdr;
  __declspec(ctm) __mem40 struct tcp_hdr *tcp_hdr;
  __declspec(ctm) __mem40 char *pbuf;
  flow_4_tuple.word64[0]= 0;
  flow_4_tuple.word64[1]= 0;

  for (;;) {
      // 1. Receive a packet
      pkt_nbi_recv(&nbi_meta, sizeof(nbi_meta));
      pbuf = pkt_ctm_ptr40(pi->isl, pi->pnum, 0);

      ip_hdr = (__mem40 struct ip4_hdr *)(pbuf + pkt_off + sizeof(struct eth_hdr));

      tcp_hdr = (__mem40 struct tcp_hdr *)(pbuf + pkt_off
                                                + sizeof(struct eth_hdr)
                                                + sizeof(struct ip4_hdr));

      // 2. Calculate flow hash
      flow_4_tuple.ip_src = ip_hdr->src;
      flow_4_tuple.ip_dst = ip_hdr->dst;
      flow_4_tuple.l4_src = tcp_hdr->sport;
      flow_4_tuple.l4_dst = tcp_hdr->dport;

      flow_hash = hash_me_crc32(&flow_4_tuple.word64, 12, HASH_SEED_VALUE);

      // 3. Create work struct
      work.isl = pi->isl;
      work.pnum = pi->pnum;
      work.plen = pi->len;
      work.seqr = nbi_meta.seqr;
      work.seq = nbi_meta.seq;
      work.hash = flow_hash;
      work.rx_port = MAC_TO_PORT(nbi_meta.port);

      work_xfer = work;

      // TODO: There are many ways to do this. Here I'm using just one ME for
      // syn processing. We could also have one ME per island to process
      // SYN packets for a certain flow group, as we increase the number of flows
      if (tcp_hdr->flags == NET_TCP_FLAG_SYN) {
          // send to the syn processing ME
          rnum = MEM_RING_GET_NUM(syn_ring);
          raddr_hi = (EMEM_ISL | 0x80) << 24;
          mem_workq_add_work(rnum, raddr_hi, &work_xfer, sizeof(work_xfer));
      }
      else {
          // All other packets: send to worker islands for processing
          // There are 4 worker islands, we need 2 bits to check which island to
          // steer this flow to
          flow_island = flow_hash & 0x3;

          if (flow_island == 0) {
            rnum = MEM_RING_GET_NUM(flow_ring_0);
          }
          else if (flow_island == 1) {
            rnum = MEM_RING_GET_NUM(flow_ring_1);
          }
          else if (flow_island == 2) {
            rnum = MEM_RING_GET_NUM(flow_ring_2);
          }
          else if (flow_island == 3) {
            rnum = MEM_RING_GET_NUM(flow_ring_3);
          }

          raddr_hi = (EMEM_ISL | 0x80) << 24;
          mem_workq_add_work(rnum, raddr_hi, &work_xfer, sizeof(work_xfer));
      }

  }
  return 0;
}
