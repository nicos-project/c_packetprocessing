
#include <nfp.h>
#include <nfp/remote_me.h>

#include <nfp/mem_atomic.h>
#include <nfp/mem_bulk.h>
__volatile __export __emem uint32_t debug[8192*64];
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
                (debug + (_idx_val % (1024 * 64))), sizeof(_dvals)); \
} while(0)
        
#define CSR_MAILBOX0_ADDR 0x170
        
__intrinsic int get_sig_number(SIGNAL *sig){
    return __signal_number(sig);
}

__intrinsic uint32_t receive_remote_message(uint8_t signal, uint8_t csr_reg, uint32_t rcv_addr){
    int signal_bit = 0x1 << (signal);
    uint32_t data = 0;
    __asm{
        local_csr_wr[local_csr_active_ctx_wakeup_events, signal_bit]
        ctx_arb[--]
    }
    if(csr_reg){
        __asm{
            local_csr_rd[__ct_const_val(local_csr_mailbox0)]
            immed[data, 0]
        }
    }
    else{

    }
    return data;
}

int main(void){
    // SIGNAL sig;
    // int mailbox0_val = 0;
    // int signal_bit = 0x1 << (1);
    // while(mailbox0_val != 32){
    // __asm{
    //         local_csr_rd[local_csr_mailbox0]
    //         immed[mailbox0_val, 0]
    //     }
    // }
    // __asm{
    //     local_csr_wr[local_csr_active_ctx_wakeup_events, signal_bit]
    //     ctx_arb[--]
    // }
    int data;
    DEBUG(0x33, 0, 0, 1);
    while(1){
        data = receive_remote_message(15, 1, local_csr_mailbox0);
        DEBUG(0x33, 0, data, 2);
    }
}