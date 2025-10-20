#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/udp.h>

#include "config.h"
#include "dma.h"

#define MAC_CHAN_PER_PORT   4
#define TMQ_PER_PORT        (MAC_CHAN_PER_PORT * 8)

#define MAC_TO_PORT(x)      (x / MAC_CHAN_PER_PORT)
#define PORT_TO_TMQ(x)      (x * TMQ_PER_PORT)

__export __shared __cls uint32_t work_count;

int main(void)
{
    // Just use one thread for now
    if (__ctx() == 0) {
        __xread  struct work_t          work_read;
        __gpr    struct work_t          work;
        SIGNAL work_sig, result_sig;
        __gpr struct pkt_ms_info msi;

        unsigned int type, island, pnum, plen, seqr, seq;
        unsigned int rnum, raddr_hi;
        __mem40 char* pbuf;
        __declspec(ctm shared) __mem40 uint16_t *data;
        __gpr uint8_t pkt_off = PKT_NBI_OFFSET + MAC_PREPEND_BYTES;

        /* Select WorkQueue to poll based on FlowGroup */
        island = __ISLAND;
        work_count = 0;

        if (island == 33) {
          work_count = 100;
          rnum = MEM_RING_GET_NUM(flow_ring_0);
          raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_0);
        }

        __mem_workq_add_thread(rnum, raddr_hi,
                        &work_read,
                        sizeof(struct work_t), sizeof(struct work_t),
                        sig_done, &work_sig);

        // Dummy result signal to self
        signal_ctx(ctx(), __signal_number(&result_sig));
        __implicit_write(&result_sig);

        for (;;) {

            __wait_for_all(&work_sig);
            work = work_read;
            __mem_workq_add_thread(rnum, raddr_hi,
                            &work_read,
                            sizeof(struct work_t), sizeof(struct work_t),
                            sig_done, &work_sig);

            type = work.type;
            if (type == WORK_TYPE_RX) {
              island = 32 + work.io.isl;
              pnum   = work.io.pnum;
              plen = work.io.plen;
              seqr = work.io.seqr;
              seq = work.io.seq;
              work_count++;
              // we might have to change the offset here
              pbuf = pkt_ctm_ptr40(island, pnum, 0);

              data = (__mem40 uint16_t *)(pbuf + pkt_off
                                               + sizeof(struct eth_hdr)
                                               + sizeof(struct ip4_hdr)
                                               + sizeof(struct udp_hdr));

              // Do nothing
              *data = 0x1234;
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
    }

    return 0;
}

/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
