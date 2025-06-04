#include <nfp.h>
#include <nfp/mem_atomic.h>
#include <nfp/mem_bulk.h>
typedef __packed struct my my_t;
__packed struct my{
    __mem40 my_t *size_8_field;
    __mem40 my_t *size_8_field2;
    uint32_t size_4_field;
    uint8_t size_1_field;
};

typedef __packed struct my2 my2_t;
__packed struct my2{
    __mem40 my2_t *size_8_field;
    __mem40 my2_t *size_8_field2;
    uint32_t size_4_field;
    uint8_t size_1_field;
    uint8_t size_1_field2;
};

struct u32_struct{
    uint32_t one;
    uint32_t two;
    uint32_t three;
};

__export __global __emem struct u32_struct exstruct = {
    1,
    2,
    3,
};

__export __global __emem short emem_short;
__export __global __emem uint32_t emem_u32;

__export __global __imem short imem_short;
__export __global __imem uint32_t imem_u32;

__export __global __ctm short ctm_short;
__export __global __ctm uint32_t ctm_u32;

__export __global __cls short cls_short;
__export __global __cls uint32_t cls_u32;

__emem short l_emem_short;
__emem uint32_t l_emem_u32;

__imem short l_imem_short;
__imem uint32_t l_imem_u32;

__ctm short l_ctm_short;
__ctm uint32_t l_ctm_u32;

__cls short l_cls_short;
__cls uint32_t l_cls_u32;

__export __global __emem __mem40 char *p;
__export __global __emem __mem40 char *q;
/* DEBUG MACROS */

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


int main(void)
{
        DEBUG(0xdeadbeef, sizeof(my2_t), sizeof(my_t), 0xdeadbeef);
	DEBUG(sizeof(uint32_t), sizeof(short), 0, 0);
	DEBUG(sizeof(emem_u32), sizeof(imem_u32), sizeof(ctm_u32), sizeof(cls_u32));
	DEBUG(sizeof(emem_short), sizeof(imem_short), sizeof(ctm_short), sizeof(cls_short));
	DEBUG(sizeof(l_emem_u32), sizeof(l_imem_u32), sizeof(l_ctm_u32), sizeof(l_cls_u32));
	DEBUG(sizeof(l_emem_short), sizeof(l_imem_short), sizeof(l_ctm_short), sizeof(l_cls_short));

	p = (__mem40 char *)&exstruct;
	p = p + sizeof(uint32_t);
	q = p + 8;
        DEBUG(exstruct.two, *p, *q, p);
		
}
