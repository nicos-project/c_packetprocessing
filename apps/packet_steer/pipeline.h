/* SPDX-License-Identifier: BSD 3-Clause License */
/* Copyright (c) 2022, University of Washington, Max Planck Institute for Software Systems, and The University of Texas at Austin */

#ifndef PIPELINE_H_
#define PIPELINE_H_

#include <stdint.h>
#include <stdlib.h>

#include <nfp.h>
#include <nfp/me.h>
#include <nfp/mem_ring.h>

/**
 * Flow Ring buffers
 */
MEM_RING_INIT(flow_ring_0,  FLOW_GRP_WQ_SIZE);

/**
 * Work types
 */
enum {
  WORK_TYPE_RX = 0,
  WORK_TYPE_TX = 1,
  WORK_TYPE_AC = 2,
  WORK_TYPE_RETX = 3,
};

struct work_t
{
  union {
    __packed struct {
      uint32_t type:2;      /*> WORK_TYPE_ */
      uint32_t rsvd0:30;

      uint32_t rsvd1;

      uint32_t flow_id:16;
      uint32_t rsvd2:16;
    };

    __packed struct {
      uint32_t type:2;      /*> WORK_TYPE_ */
      uint32_t cbs:2;       /*> CTM buffer size as a multiple of 256 */
      uint32_t isl:2;       /*> NOTE: Valid island numbers are 32, 33, 34, 35. Add +32 to use in NFP APIs */
      uint32_t pnum:10;
      uint32_t seq:16;

      uint32_t force:1;     /*> Force transmission */
      uint32_t bls:2;       /*> Buffer list of the MU buffer */
      uint32_t muptr:29;    /*> Pointer to the MU buffer >>11 */

      uint32_t flow_id:16;
      uint32_t seqr:5;
      uint32_t plen:11;     /*> Payload length */
    } io;

    __packed struct {
      uint32_t type:2;      /*> WORK_TYPE_ */
      uint32_t fin:1;
      uint32_t rx_bump:29;

      uint32_t rsvd:3;     /*> May be used for higher bits of flow_id */
      uint32_t tx_bump:29;

      uint32_t flow_id:16;
      uint32_t desc_idx:16;
    } ac;

    uint32_t __raw[3];
  };
};

#endif /* PIPELINE_H_ */
