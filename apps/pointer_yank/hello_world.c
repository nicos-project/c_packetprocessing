#include <nfp.h>

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


__export __global __emem_n(0) int test = 0xbeef;

int main(void){
    /**
     * We need the volatile keyword here, or to do an explicit write.
     * Even when using *<symbol> the compiler might not generate an
     * explicit write/read
     */
    
    __mem40 int *pointer = &test; 
    uint64_t p;
    int i;
    __xwrite int code = 0xc0de;

    if(ctx() == 0){
        DEBUG(ctx(), *pointer, 0, 0);
        for(i = 0; i < 500; i++){
        }    
        *pointer = 0xc0de;
        //mem_write32(&code, pointer, 4);
    }
    else if(ctx() == 1){
        while(*pointer == 0xbeef){
        }
        DEBUG(ctx(), *pointer, 0, 0);
    }
}

