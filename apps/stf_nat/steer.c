#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
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
  __gpr uint32_t ip_src;
  __gpr struct flow_four_tuple flow_4_tuple;
  __gpr uint32_t lan_or_wan;
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
      // First, we need to decide which direction the flow is in (LAN or WAN).
      // For traffic that arrives on the WAN port, the hash will end up being
      // different if we don't flip the src/dst. We need the same hash so that the flow
      // goes to the same island irrespective of the direction.
      //
      // Assume for now that the LAN IPs are in range 192.168.1.0/24
      // Alternatively, we could also check the destination IP and see if it matches
      // the WAN IP to make this decision. But when we test the firewall, we don't
      // have a WAN IP, we just have incoming or outgoing traffic.
      //
      ip_src = ip_hdr->src;
      ip_src = ip_src >> 8; // TODO: it should be right shifted by 32 - prefix length

      if (!(ip_src ^ 0x00C0A801)) {
          // Traffic originating on the LAN port
          flow_4_tuple.ip_src = ip_hdr->src;
          flow_4_tuple.ip_dst = ip_hdr->dst;
          flow_4_tuple.l4_src = tcp_hdr->sport;
          flow_4_tuple.l4_dst = tcp_hdr->dport;
          lan_or_wan = 0;
      }
      else {
          // Traffic originating on the WAN port
          flow_4_tuple.ip_src = ip_hdr->dst;
          flow_4_tuple.ip_dst = ip_hdr->src;
          flow_4_tuple.l4_src = tcp_hdr->dport;
          flow_4_tuple.l4_dst = tcp_hdr->sport;
          lan_or_wan = 1;
      }

      flow_hash = hash_me_crc32(&flow_4_tuple.word64, 12, HASH_SEED_VALUE);

      // 3. Send to another island for processing
      work.isl = pi->isl;
      work.pnum = pi->pnum;
      work.plen = pi->len;
      work.seqr = nbi_meta.seqr;
      work.seq = nbi_meta.seq;
      work.hash = flow_hash;
      work.rx_port = MAC_TO_PORT(nbi_meta.port);
      work.lan_or_wan = lan_or_wan;

      work_xfer = work;

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
  return 0;
}
