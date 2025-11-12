#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <nfp/mem_bulk.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/udp.h>

#include "config.h"

int main(void)
{
    // Just use one thread for now
    __gpr struct pkt_ms_info msi;
    __gpr int in_port;
    // __gpr uint16_t me_num = __MENUM;
    // __gpr uint16_t t_num = __ctx();
    // __gpr uint16_t isl_num = __ISLAND;
    __gpr uint8_t pkt_off = PKT_NBI_OFFSET + MAC_PREPEND_BYTES;
    __xread struct nbi_meta_catamaran nbi_meta;
    __xread struct nbi_meta_pkt_info *pi = &nbi_meta.pkt_info;
    __declspec(ctm shared) __mem40 char *pbuf;
    __xread uint32_t ingress_timestamp;
    __xwrite uint32_t timestamp_write;
    __xwrite uint32_t offset_write;
    __mem40 uint32_t *data_ptr;
    __gpr uint32_t egress_ts_offset;

    for (;;) {
        // Receive a packet
        pkt_nbi_recv(&nbi_meta, sizeof(nbi_meta));
        in_port = MAC_TO_PORT(nbi_meta.port);
        pbuf = pkt_ctm_ptr40(pi->isl, pi->pnum, 0);
        
        // Read ingress timestamp (first int after PKT_NBI_OFFSET)
        mem_read32(&ingress_timestamp, (__mem40 void *)(pbuf + PKT_NBI_OFFSET), sizeof(uint32_t));
        
        // Calculate pointer to data after UDP header
        data_ptr = (__mem40 uint32_t *)(pbuf + pkt_off
                                         + sizeof(struct eth_hdr)
                                         + sizeof(struct ip4_hdr)
                                         + sizeof(struct udp_hdr));
        
        // Write ingress timestamp to packet data (after UDP header)
        timestamp_write = ingress_timestamp;
        mem_write32(&timestamp_write, (__mem40 void *)data_ptr, sizeof(uint32_t));
        
        // Calculate offset for egress timestamp (position after ingress timestamp in payload)
        egress_ts_offset = sizeof(struct eth_hdr) + sizeof(struct ip4_hdr) 
                          + sizeof(struct udp_hdr) + sizeof(uint32_t);

        // Send the packet back
        pkt_mac_egress_cmd_write(pbuf, pkt_off, 1, 1);
        msi = pkt_msd_write(pbuf, pkt_off - 4);
        
        // Write offset to the position after ingress timestamp in prepend area
        // This tells the NIC where to write the egress timestamp
        offset_write = egress_ts_offset;
        mem_write32(&offset_write, (__mem40 void *)(pbuf + PKT_NBI_OFFSET + sizeof(uint32_t)), sizeof(uint32_t));

        pkt_nbi_send(pi->isl,
                     pi->pnum,
                     &msi,
                     pi->len - MAC_PREPEND_BYTES + 4,
                     NBI,
                     PORT_TO_TMQ(in_port), // same port as what we received it on
                     nbi_meta.seqr, nbi_meta.seq, PKT_CTM_SIZE_256);
    }

    return 0;
}

/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
