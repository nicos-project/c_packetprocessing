#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <blm.h>
#include <assert.h>

#include "config.h"

/* B0 and later allow the modification script at an offset up to 128B */
#if (__REVISION_MIN < __REVISION_B0)
#define MS_MAX_OFF  64
#else
#define MS_MAX_OFF  128
#endif

__intrinsic struct pkt_ms_info
pkt_gen_msi_info(unsigned char off)
{
    __gpr struct pkt_ms_info msi;

    ctassert(__is_ct_const(off));

    /* Check for an illegal packet offset for direct modification script */
    __RT_ASSERT((off >= 16) && (off <= (MS_MAX_OFF + 16)));

    /* Check if a no-op modification script is possible */
    if (off <= MS_MAX_OFF && (off & 7) == 0) {
        /* Write a no-op modification script right before the packet start */
        msi.off_enc = (off >> 3) - 2;
    } else {
        /* Determine a starting offset for the 8-byte modification script that
         * is closest to the start of packet, that is 8-byte aligned, and that
         * is still within the 120-byte (56-byte for A0) offset limit */
        unsigned char ms_off = MS_MAX_OFF - 8;

        if (off < MS_MAX_OFF)
            ms_off = (off & ~0x7) - 8;

        /* write a delete modification script to remove any excess bytes */
        msi.off_enc = (ms_off >> 3) - 1;
    }

    /* Set the length adjustment to point to the start of packet. */
    msi.len_adj = off;

    return msi;
}

int main(void)
{
    if (__ctx() == 0) {
        __gpr struct pkt_ms_info msi;
        __gpr unsigned int island, pnum, plen, seqr, seq, muptr, bls;
        __gpr unsigned int rnum, raddr_hi;
        __gpr uint8_t pkt_off = PKT_NBI_OFFSET + MAC_PREPEND_BYTES;
        __gpr uint8_t rx_port;
        __mem40 char* pbuf;
        __gpr uint32_t counter = 0;
        __xread struct nbi_meta_catamaran nbi_meta;
        __xread struct nbi_meta_pkt_info *pi = &nbi_meta.pkt_info;

        for (;;) {
            pkt_nbi_recv(&nbi_meta, sizeof(nbi_meta));
            rx_port = MAC_TO_PORT(nbi_meta.port);
            island = pi->isl;
            pnum = pi->pnum;
            plen = pi->len;
            seqr = nbi_meta.seqr;
            seq = nbi_meta.seq;
            muptr = pi->muptr;
            bls = pi->bls;

            counter++;

            // Drop every other packet
            // Send packets at very low rate maybe ~1 mbps (we use only one ME and island)
            // You should observe an exact 50% drop
            if ((counter & 0x1) == 0) {
                // Send the packet back
                pbuf = pkt_ctm_ptr40(island, pnum, 0);
                pkt_mac_egress_cmd_write(pbuf, pkt_off, 1, 1);
                msi = pkt_msd_write(pbuf, pkt_off - 4);

                pkt_nbi_send(island,
                             pnum,
                             &msi,
                             plen - MAC_PREPEND_BYTES + 4,
                             0,
                             PORT_TO_TMQ(rx_port), // same port as what we received it on
                             seqr, seq, PKT_CTM_SIZE_256);
            }
            else {
                // Why should it be `PKT_NBI_OFFSET + MAC_PREPEND_BYTES - 2`?
                msi = pkt_gen_msi_info(PKT_NBI_OFFSET + MAC_PREPEND_BYTES - 2);
                pkt_nbi_drop_seq(island,
                                 pnum,
                                 &msi,
                                 plen + 4,
                                 0,
                                 PORT_TO_TMQ(rx_port),
                                 seqr,
                                 seq, PKT_CTM_SIZE_256);

                blm_buf_free(muptr, bls);
                pkt_ctm_free(island, pnum);
           }
        }
    }

    return 0;
}

/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
