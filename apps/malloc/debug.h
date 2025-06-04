/* DEBUG MACROS */
#ifndef __DEBUG__
#define __DEBUG__

#include <nfp/mem_atomic.h>

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

#endif