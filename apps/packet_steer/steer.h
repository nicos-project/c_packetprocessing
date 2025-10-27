#ifndef __STEER_H_
#define __STEER_H_

#include <stdint.h>
#include <stdlib.h>

#include <nfp.h>
#include <nfp/me.h>
#include <nfp/mem_ring.h>

/**
 * Flow Ring buffers
 */
MEM_RING_INIT(flow_ring_0,  FLOW_GRP_WQ_SIZE);
MEM_RING_INIT(flow_ring_1,  FLOW_GRP_WQ_SIZE);
MEM_RING_INIT(flow_ring_2,  FLOW_GRP_WQ_SIZE);
MEM_RING_INIT(flow_ring_3,  FLOW_GRP_WQ_SIZE);

__packed struct work_t
{
  uint32_t isl:6;
  uint32_t pnum:10;
  uint32_t seq:16;
  uint32_t seqr:5;
  uint32_t plen:11;
  uint32_t hash:32;
  uint32_t rx_port:3;
} __align(4);

#endif /* __STEER_H_ */
