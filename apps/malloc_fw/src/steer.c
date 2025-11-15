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
#include "dependencies/hash-table/flow_table.h"

#define HASH_SEED_VALUE 0

struct flow_four_tuple {
    union {
        struct {
            uint32_t ip_src;
            uint32_t ip_dst;
            uint16_t tcp_src;
            uint16_t tcp_dst;
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
  ipv4_5_tuple_t flow_5_tuple;

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
    // TODO: For NAT, we'll have to perform the translation before we calculate
    // the hash so that we have the right island. We can use separate threads
    // for doing the WAN to LAN translation instead of steering them to
    // different islands.
    //
    ip_src = ip_hdr->src;
    ip_src = ip_src >> 8; // TODO: it should be right shifted by 32 - prefix length

    if (!(ip_src ^ 0x00C0A801)) {
      // Traffic originating on the LAN port
      flow_5_tuple.src_ip = ip_hdr->src;
      flow_5_tuple.dst_ip = ip_hdr->dst;
      flow_5_tuple.sport = tcp_hdr->sport;
      flow_5_tuple.dport = tcp_hdr->dport;
      flow_5_tuple.proto = 0x06;
      flow_5_tuple.padding[0] = 0;
      flow_5_tuple.padding[1] = 0;
      flow_5_tuple.padding[2] = 0;
      lan_or_wan = 0;
    }
    else {
      // Traffic originating on the WAN port
      flow_5_tuple.src_ip = ip_hdr->dst;
      flow_5_tuple.dst_ip = ip_hdr->src;
      flow_5_tuple.sport = tcp_hdr->dport;
      flow_5_tuple.dport = tcp_hdr->sport;
      flow_5_tuple.proto = 0x06;
      flow_5_tuple.padding[0] = 0;
      flow_5_tuple.padding[1] = 0;
      flow_5_tuple.padding[2] = 0;
      lan_or_wan = 1;
    }

    /**
     * Use 16 here to hash the entire 5-tuple structure (including protocol and padding).
     * This must match the hash length used in flow_table.c
    */
    flow_hash = hash_me_crc32((void *)&flow_5_tuple, 16, HASH_SEED_VALUE);

    // 3. Send to another island for processing
    work.isl = pi->isl;
    work.pnum = pi->pnum;
    work.plen = pi->len;
    work.seqr = nbi_meta.seqr;
    work.seq = nbi_meta.seq;
    work.five_tuple = flow_5_tuple;
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
