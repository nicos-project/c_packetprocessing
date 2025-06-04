#include <nfp.h>
#include <stdint.h>
#include <nfp_cluster_target_ring.h>
#include <../../flowenv/me/lib/nfp/mem_ring.h>


//ring 0
__export __global __ctm_n(33) __addr40 __align(128 * sizeof(uint32_t)) uint32_t ctm_ring_head[128];
__export __global __emem_n(1) __addr40 __align(128 * sizeof(uint32_t)) uint32_t test[128];
MEM_RING_INIT_MU(ctm_ring, 2048, emem0)

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

void mem_ring_func_test(){
    SIGNAL sig;
    __xrw uint32_t wxfer = 0xdeadbeef;
    __xread uint32_t rxfer;
    __gpr uint32_t val;
    if (__ctx() == 0){
		mem_ring_put(MEM_RING_GET_NUM(ctm_ring), MEM_RING_GET_MEMADDR(ctm_ring), &wxfer, 4);
        wxfer = 0xc0debad0;
		mem_ring_put(MEM_RING_GET_NUM(ctm_ring), MEM_RING_GET_MEMADDR(ctm_ring), &wxfer, 4);
    }

	val = mem_ring_get(MEM_RING_GET_NUM(ctm_ring), MEM_RING_GET_MEMADDR(ctm_ring), &rxfer, 4);
    if(val == -1){
        __asm local_csr_wr[local_csr_mailbox0, 0xff];
    }
    else{
        __asm local_csr_wr[local_csr_mailbox1, rxfer];
    }

    val = mem_ring_get(MEM_RING_GET_NUM(ctm_ring), MEM_RING_GET_MEMADDR(ctm_ring), &rxfer, 4);
    if(val == -1){
        __asm local_csr_wr[local_csr_mailbox3, 0xff];
    }
    else{
        __asm local_csr_wr[local_csr_mailbox2, rxfer];
    }
}

int main(void)
{
	ctm_ring_full();
    return 0;
}
