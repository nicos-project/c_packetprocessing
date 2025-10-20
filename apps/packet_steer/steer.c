#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>

#include "config.h"
#include "packet_defs.h"
#include "dma.h"

__export __shared __cls uint32_t count;

int main() {
  if (ctx() == 0) {
      __gpr struct work_t work;
      __gpr uint32_t seq, seqr;
      __gpr unsigned int rnum, raddr_hi;
      __xwrite struct work_t work_xfer;
      __xread struct nbi_meta_catamaran nbi_meta;
      __xread struct nbi_meta_pkt_info *pi = &nbi_meta.pkt_info;

      count = 0;

      for (;;) {
          // 1. Receive a packet
          pkt_nbi_recv(&nbi_meta, sizeof(nbi_meta));

          if(pi->len > 0) {
              count++;
          }

          // 2. TODO: Calculate flow hash
          work.io.type    = WORK_TYPE_RX;
          work.io.cbs     = 0;
          work.io.isl     = pi->isl - 32;
          work.io.pnum    = pi->pnum;
          work.io.bls     = pi->bls;
          work.io.muptr   = pi->muptr;
          work.io.flow_id = 0;
          work.io.plen    = pi->len;
          work.io.seqr    = nbi_meta.seqr;
          work.io.seq    = nbi_meta.seq;

          // 3. Send to another island for processing
          work_xfer = work;
          rnum = MEM_RING_GET_NUM(flow_ring_0);
          raddr_hi = (EMEM_ISL | 0x80) << 24;
          mem_workq_add_work(rnum, raddr_hi, &work_xfer, sizeof(work_xfer));
      }
  }
  return 0;
}
