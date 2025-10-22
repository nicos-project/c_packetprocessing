#include <nfp.h>
#include <nfp/remote_me.h>
#include <assert.h>

#define CT_REFLECT_ISL_MASK    ((1 << 6) - 1)
#define CT_REFLECT_MASTER_MASK ((1 << 4) - 1)
#define CT_REFLECT_REG_MASK    ((1 << 8) - 1)

#define CT_REFLECT_MAX_ME_NUM  (CT_REFLECT_MASTER_MASK - 4)

#define MEREG_CT_REFLECT_ADDR(_isl, _me, _is_csr, _addr)                  \
    ((((_isl) & CT_REFLECT_ISL_MASK) << 24) | ((_is_csr) ? 0x10000 : 0) | \
     ((((_me) + 4) & CT_REFLECT_MASTER_MASK) << 10) |                     \
     (((_addr) & CT_REFLECT_REG_MASK) << 2))

#define MEREG_CT_REFLECT_ADDR(_isl, _me, _is_csr, _addr)                  \
    ((((_isl) & CT_REFLECT_ISL_MASK) << 24) | ((_is_csr) ? 0x10000 : 0) | \
     ((((_me) + 4) & CT_REFLECT_MASTER_MASK) << 10) |                     \
     (((_addr) & CT_REFLECT_REG_MASK) << 2))


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

__intrinsic void __remote_me_reg_write_signal_remote(__xwrite void *data, unsigned int island,
                                  unsigned int me, unsigned int reg_is_csr,
                                  unsigned int reg_addr, size_t size,
                                  sync_t sync, SIGNAL *local_sig)
{
    unsigned int addr = MEREG_CT_REFLECT_ADDR(island, me, reg_is_csr,
                                              reg_addr);
    unsigned int cnt = size >> 2;
    unsigned int local_sig_num = __signal_number(local_sig);
    DEBUG(0x32, 0, local_sig_num, 2);     
    ctassert(__is_write_reg(data));
    //remote_me_reg_check_params(island, me, reg_is_csr, reg_addr, size);
    ctassert(__is_ct_const(sync));
    ctassert(sync == sig_done || sync == ctx_swap);

    /* Signal local ME only. */
    if (sync == sig_done) {
        __asm ct[reflect_write_sig_remote, *data, addr, 0, cnt], sig_done[*local_sig];
    } else {
        __asm ct[reflect_write_sig_remote, *data, addr, 0, cnt], ctx_swap[*local_sig];
    }
}


__intrinsic void message_remote_thread(__xwrite int *data, uint8_t size, uint8_t reg_is_csr, uint8_t reg_addr, uint8_t island, uint8_t me, uint8_t thread, uint8_t signal){
    //write
    uint32_t arg = (island << 24) | ((me + 4) << 9) | (thread << 6) | (signal << 2);
    remote_me_reg_write_signal_local(data, island, me, reg_is_csr, reg_addr, size);
    DEBUG(0x32, 0, arg, 2);
    //signal remote thread
    __asm{
        ct[interthread_signal, --, arg, 0, 1]
    }
}
        
int main(void){
    __xwrite int data = 0xf0f0f0f0;
    int i;
    unsigned int remote_island = 33;
    unsigned int remote_me = 0;
    unsigned int reg_is_csr = 1;
    unsigned int reg_addr = local_csr_mailbox_0;
    unsigned int size = 4;
    SIGNAL i32_sig;
    SIGNAL *sig_ptr = (SIGNAL *) 4;
    DEBUG(0x32, 0, 0, 1);
    for(i = 0; i < 100; i++){
        data = i;
        message_remote_thread(&data, size, reg_is_csr, reg_addr, 33, 0, 0, 15);
    }
    DEBUG(0x32, 0, 0, 3);
}