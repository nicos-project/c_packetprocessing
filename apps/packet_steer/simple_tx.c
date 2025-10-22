#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/udp.h>

#include "config.h"
#include "pipeline.h"

#define MAC_CHAN_PER_PORT   4
#define TMQ_PER_PORT        (MAC_CHAN_PER_PORT * 8)

#define MAC_TO_PORT(x)      (x / MAC_CHAN_PER_PORT)
#define PORT_TO_TMQ(x)      (x * TMQ_PER_PORT)

int main(void)
{
    // Just use one thread for now
    if (__ctx() == 0) {
        __gpr struct work_t work;
        __gpr struct pkt_ms_info msi;
        __gpr unsigned int type, island, pnum, plen, seqr, seq;
        __gpr unsigned int rnum, raddr_hi;
        __gpr uint8_t pkt_off = PKT_NBI_OFFSET + MAC_PREPEND_BYTES;
        __mem40 char* pbuf;
        __declspec(ctm shared) __mem40 uint16_t *data;
        __xread  struct work_t work_read;
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

        for (;;) {
            __mem_workq_add_thread(rnum, raddr_hi,
                            &work_read,
                            sizeof(struct work_t), sizeof(struct work_t),
                            sig_done, &work_sig);
            __wait_for_all(&work_sig);

            work = work_read;
            island = work.isl;
            pnum   = work.pnum;
            plen = work.plen;
            seqr = work.seqr;
            seq = work.seq;

            pbuf = pkt_ctm_ptr40(island, pnum, 0);
            /*data = (__mem40 uint16_t *)(pbuf + pkt_off
                                             + sizeof(struct eth_hdr)
                                             + sizeof(struct ip4_hdr)
                                             + sizeof(struct udp_hdr));

            *data = __ISLAND;
            data += 1;
            *data = 0x1234;*/

            // Send the packet back
            pkt_mac_egress_cmd_write(pbuf, pkt_off, 1, 1);
            msi = pkt_msd_write(pbuf, pkt_off - 4);
            pkt_nbi_send(island,
                         pnum,
                         &msi,
                         plen - MAC_PREPEND_BYTES + 4,
                         0, // NBI is 0
                         PORT_TO_TMQ(0), // same port as what we received it on
                         seqr, seq, PKT_CTM_SIZE_256);
        }
    }

    return 0;
}

/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
