#include <nfp.h>
#include <stdint.h>
#include <nfp_cluster_target_ring.h>
#include <../../flowenv/me/lib/nfp/mem_ring.h>


#include <nfp/mem_atomic.h>
#include <nfp/mem_bulk.h>
__volatile __export __emem uint32_t debug[8192];
__volatile __export __emem uint32_t debug_idx;
#define DEBUG(_a, _b, _c, _d) do { \
    __xrw uint32_t _idx_val = 4; \
    __xwrite uint32_t _dvals[4]; \
    mem_test_add(&_idx_val, \
            (__mem40 void *)&debug_idx, sizeof(_idx_val)); \
    _dvals[0] = _a; \
    _dvals[1] = _b; \
    _dvals[2] = _c; \
    _dvals[3] = _d; \
    mem_write_atomic(_dvals, (__mem40 void *)\
                    (debug + (_idx_val % (8192))), sizeof(_dvals)); \
    } while(0)

//ring 0
__export __global __ctm_n(33) __addr40 __align(128 * sizeof(uint32_t)) uint32_t ctm_ring_head[128];
__export __global __emem_n(1) __addr40 __align(128 * sizeof(uint32_t)) uint32_t test[128];
MEM_RING_INIT_MU(emem_ring, 2048, emem0)
MEM_RING_INIT_MU(emem1_ring, 2048, emem1)

void ctm_ring_empty(){
	__xread uint32_t rxfer;
	__gpr uint32_t val;
	SIGNAL sig;
	__gpr uint32_t old_mailbox;
	int i;

    if (__ctx() == 0){
        cmd_cluster_target_ring_init_ptr40(0, ctm_ring_head, CT_RING_SIZE_128, CT_RING_FULL | CT_RING_EMPTY, ctx_swap, &sig);
	}

	for(i = 0; i < 100; i++){
    	cmd_cluster_target_ring_get(&rxfer, 33, 0, 1, ctx_swap, &sig);
    	val = rxfer;
    	if(val == 0){
			__asm{
				local_csr_rd[local_csr_mailbox0]
				immed[old_mailbox, 0]
			}
			old_mailbox++;
       	 	__asm local_csr_wr[local_csr_mailbox0, old_mailbox];
    	}
    	else{
			__asm{
				local_csr_rd[local_csr_mailbox1]
				immed[old_mailbox, 0]
			}
			old_mailbox++;
       		 __asm local_csr_wr[local_csr_mailbox1, old_mailbox];
    	}
	}
}

void ctm_ring_full(){
	__xread uint32_t rxfer;
	__gpr uint32_t val;
    __xrw uint32_t wxfer = __ctx();
	SIGNAL sig;
	__gpr uint32_t old_mailbox;
	int i;

    if(__ctx() == 0){
        cmd_cluster_target_ring_init_ptr40(0, ctm_ring_head, CT_RING_SIZE_128, CT_RING_FULL | CT_RING_EMPTY, ctx_swap, &sig);
	}

	for(i = 0; i < 50; i++){
		cmd_cluster_target_ring_put(&wxfer, 33, 0, 1, ctx_swap, &sig);
	}
}


void ctm_ring_func_test(){
    SIGNAL sig;
    __xrw uint32_t wxfer = 0xdeadbeef;
    __xread uint32_t rxfer;
    __gpr uint32_t val;
    if(__ctx() == 0){
		test[0] = 5;
        cmd_cluster_target_ring_init_ptr40(0, ctm_ring_head, CT_RING_SIZE_128, CT_RING_FULL | CT_RING_EMPTY, ctx_swap, &sig);

		cmd_cluster_target_ring_put(&wxfer, 33, 0, 1, ctx_swap, &sig);
        wxfer = 0xc0debad0;
        cmd_cluster_target_ring_put(&wxfer, 33, 0, 1, ctx_swap, &sig);
    }
    

    cmd_cluster_target_ring_get(&rxfer, 33, 0, 1, ctx_swap, &sig);
    val = rxfer;
    if(val == 0){
        __asm local_csr_wr[local_csr_mailbox0, 0xff];    
    }
    else{
        __asm local_csr_wr[local_csr_mailbox1, val];
    }

    cmd_cluster_target_ring_get(&rxfer, 33, 0, 1, ctx_swap, &sig);
    val = rxfer;
    if(val == 0){
        __asm local_csr_wr[local_csr_mailbox3, 0xff];
    }
    else{
        __asm local_csr_wr[local_csr_mailbox2, val];
    }
}

void emem_ring_func_test(){
    SIGNAL sig;
    __xrw uint32_t wxfer = local_csr_read(local_csr_active_ctx_sts);
    __xread uint32_t rxfer;
    __gpr uint32_t val;
    if(__ctx() == 0 && wxfer == 0xc0000820){
		mem_ring_put(MEM_RING_GET_NUM(emem_ring), MEM_RING_GET_MEMADDR(emem_ring), &wxfer, 4);
		mem_ring_put(MEM_RING_GET_NUM(emem_ring), MEM_RING_GET_MEMADDR(emem_ring), &wxfer, 4);
		mem_ring_put(MEM_RING_GET_NUM(emem_ring), MEM_RING_GET_MEMADDR(emem_ring), &wxfer, 4);
		mem_ring_put(MEM_RING_GET_NUM(emem_ring), MEM_RING_GET_MEMADDR(emem_ring), &wxfer, 4);
    }
    else if(__ctx() == 0){
		mem_ring_put(MEM_RING_GET_NUM(emem_ring), MEM_RING_GET_MEMADDR(emem_ring), &wxfer, 4);
        //wxfer = 0xc0debad0;
		mem_ring_put(MEM_RING_GET_NUM(emem_ring), MEM_RING_GET_MEMADDR(emem_ring), &wxfer, 4);
    }

	val = mem_ring_get(MEM_RING_GET_NUM(emem_ring), MEM_RING_GET_MEMADDR(emem_ring), &rxfer, 4);
    if(val == -1){
        __asm local_csr_wr[local_csr_mailbox0, 0xff];
    }
    else{
        __asm local_csr_wr[local_csr_mailbox1, rxfer];
    }

    val = mem_ring_get(MEM_RING_GET_NUM(emem_ring), MEM_RING_GET_MEMADDR(emem_ring), &rxfer, 4);
    if(val == -1){
        __asm local_csr_wr[local_csr_mailbox3, 0xff];
    }
    else{
        __asm local_csr_wr[local_csr_mailbox2, rxfer];
    }
}

void emem1_ring_func_test(){
    SIGNAL sig;
    __xrw uint32_t wxfer = local_csr_read(local_csr_active_ctx_sts);
    __xread uint32_t rxfer;
    __gpr uint32_t val;
    // if(__ctx() == 0 && wxfer == 0xc0000820){
    //     mem_ring_put(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &wxfer, 4);
    //     mem_ring_put(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &wxfer, 4);
    //     mem_ring_put(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &wxfer, 4);
    //     mem_ring_put(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &wxfer, 4);
    // }
    //else 
    if(__ctx() == 0){
        mem_ring_put(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &wxfer, 4);
        //wxfer = 0xc0debad0;
        mem_ring_put(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &wxfer, 4);
    }

    val = mem_ring_get(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &rxfer, 4);
    if(val == -1){
        __asm local_csr_wr[local_csr_mailbox0, 0xff];
        __asm local_csr_wr[local_csr_mailbox1, rxfer];
    }
    else{
        __asm local_csr_wr[local_csr_mailbox1, rxfer];
    }

    val = mem_ring_get(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &rxfer, 4);
    if(val == -1){
        __asm local_csr_wr[local_csr_mailbox3, 0xff];
        __asm local_csr_wr[local_csr_mailbox1, rxfer];
    }
    else{
        __asm local_csr_wr[local_csr_mailbox2, rxfer];
    }
}


void parallel_producer_consumer_test(){
    uint32_t ctx_status, MENumber, IslandID, ctx, i;
    __xrw uint64_t val;
    uint32_t val_high, val_low;

    ctx_status = local_csr_read(local_csr_active_ctx_sts);
    MENumber = ((ctx_status & 0x00000078) >> 3) - 4;
    IslandID = ((ctx_status & 0x7e000000) >> 25);
    ctx = __ctx();



    if(IslandID == 32 && MENumber == 0 && ctx == 0){
        for(i = 0; i < -1; i++){
            val = i;
            mem_ring_put(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &val, 8);
        }
    }
    else{
        while(1){
            if(mem_ring_get(MEM_RING_GET_NUM(emem1_ring), MEM_RING_GET_MEMADDR(emem1_ring), &val, 8) != -1){
                val_high = val >> 32;
                val_low = (uint32_t) val;
                DEBUG(0, 0, val_high, val_low);
            }
        }
    }
}

int main(void)
{   
	parallel_producer_consumer_test();
    return 0;
}
