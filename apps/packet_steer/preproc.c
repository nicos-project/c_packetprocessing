#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/udp.h>

#include "config.h"
#include "packet_defs.h"
#include "dma.h"

__export __shared __cls uint32_t count;

int main() {
  if (ctx() == 0) {
      __gpr struct work_t work;
      __xread struct pkt_raw_t pkt;
      __xwrite struct work_t work_xfer;
      SIGNAL pkt_sig;
      uint32_t seq, seqr;
      uint32_t flow_grp = 0;  // Using flow group 0
      unsigned int rnum, raddr_hi;

      count = 0;

      for (;;) {
          // 1. Receive a packet
          __pkt_nbi_recv_with_hdrs(&pkt, sizeof(struct pkt_raw_t), PKT_NBI_OFFSET, sig_done, &pkt_sig);

          __wait_for_all(&pkt_sig);

          if(pkt.meta.pkt_info.len > 0) {
              count++;
          }

          work.io.type    = WORK_TYPE_RX;
          work.io.cbs     = compute_ctm_size(&pkt.meta.pkt_info);
          work.io.isl     = pkt.meta.pkt_info.isl - 32;
          work.io.pnum    = pkt.meta.pkt_info.pnum;
          work.io.bls     = pkt.meta.pkt_info.bls;
          work.io.muptr   = pkt.meta.pkt_info.muptr;
          work.io.flow_id = 0;
          work.io.plen    = pkt.meta.pkt_info.len;
          work.io.seqr    = pkt.meta.seqr;
          work.io.seq    = pkt.meta.seq;


          // 2. TODO: Calculate flow hash

          // 3. Send to another island for processing

          // Send directly to memory ring (no reordering)
          work_xfer = work;
          rnum = MEM_RING_GET_NUM(flow_ring_0);
          raddr_hi = (EMEM_ISL | 0x80) << 24;
          mem_workq_add_work(rnum, raddr_hi, &work_xfer, sizeof(work_xfer));

          __implicit_read(&pkt);
          __implicit_write(&pkt_sig);
      }
  }
  return 0;
}
