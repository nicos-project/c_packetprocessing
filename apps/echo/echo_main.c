#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>

#include "config.h"

int main(void)
{
    // Just use one thread for now
    if (__ctx() == 0) {
        __gpr struct pkt_ms_info msi;
        __gpr int in_port;
        __gpr uint8_t pkt_off = PKT_NBI_OFFSET + MAC_PREPEND_BYTES;
        __xread struct nbi_meta_catamaran nbi_meta;
        __xread struct nbi_meta_pkt_info *pi = &nbi_meta.pkt_info;
        __declspec(ctm shared) __mem40 char *pbuf;

        for (;;) {
            // Receive a packet
            pkt_nbi_recv(&nbi_meta, sizeof(nbi_meta));
            in_port = MAC_TO_PORT(nbi_meta.port);
            pbuf = pkt_ctm_ptr40(pi->isl, pi->pnum, 0);

            // Do nothing

            // Send the packet back
            pkt_mac_egress_cmd_write(pbuf, pkt_off, 1, 1);
            msi = pkt_msd_write(pbuf, pkt_off - 4);
            pkt_nbi_send(pi->isl,
                         pi->pnum,
                         &msi,
                         pi->len - MAC_PREPEND_BYTES + 4,
                         NBI,
                         PORT_TO_TMQ(in_port), // same port as what we received it on
                         nbi_meta.seqr, nbi_meta.seq, PKT_CTM_SIZE_256);
        }
    }

    return 0;
}

/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
