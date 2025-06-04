#include <nfp.h>
#include <nfp_intrinsic.h>
#include <rtl.h>
//#include "debug.h"
#include "malloc.h"

int test_malloc(){
    __addr40 int *test_pointer;
    __xwrite int number = 7;
    unsigned int addr_hi, addr_lo;
    int read_number = 0;
    test_pointer = (__addr40 int *) malloc(sizeof(int));
    if(!test_pointer) {
        return !test_pointer;
    }


    addr_hi = ((unsigned long long int) test_pointer >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)test_pointer & 0xffffffff;

    __asm{
        mem[write32_be, number, addr_hi, <<8, addr_lo, 1];
    }

    read_number = *test_pointer;
    return read_number;
}


int asynch_memory_demo(){
    __addr40 int *emem_pointer;
    __addr40 int *imem_pointer;
    __addr40 int *ctm_pointer;
    __xwrite int number = 15;
    __xwrite int number2 = 2;
    unsigned int addr_hi, addr_lo;
    int read_number = 0;
    SIGNAL my_signal;
    emem_pointer = (__addr40 int *) pick_emem0(sizeof(int));
    if(!emem_pointer) {
        return !emem_pointer;
    }


    addr_hi = ((unsigned long long int) emem_pointer >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)emem_pointer & 0xffffffff;

    __asm{
        mem[write32_le, number, addr_hi, <<8, addr_lo, 1];
    }

   imem_pointer = (__addr40 int *) pick_imem(sizeof(int)); 


    addr_hi = ((unsigned long long int) imem_pointer >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)imem_pointer & 0xffffffff;

    number = 2;
    __asm{
        mem[write32_le, number, addr_hi, <<8, addr_lo, 1], ctx_swap[my_signal];
    }

    return 0;
}

int test_movement(){
    __addr40 int *emem_pointer;
    __addr40 int *imem_pointer;
    __addr40 int *ctm_pointer;
    __xwrite int number = 15;
    unsigned int addr_hi, addr_lo;
    SIGNAL my_signal;
    emem_pointer = (__addr40 int *) pick_emem0(sizeof(int));
    if(!emem_pointer) {
        return !emem_pointer;
    }


    addr_hi = ((unsigned long long int) emem_pointer >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)emem_pointer & 0xffffffff;

    __asm{
        mem[write32, number, addr_hi, <<8, addr_lo, 1], ctx_swap[my_signal];
    }

   imem_pointer = (__addr40 int *) pick_imem(sizeof(int)); 
   ctm_pointer = (__addr40 int *) pick_ctm33(sizeof(int));

    ua_memcpy_mem40_mem40((__addr40 void *)(imem_pointer), 0, (__addr40 void *)emem_pointer, 0, 4); 
    ua_memcpy_mem40_mem40((__addr40 void *)ctm_pointer, 0, (__addr40 void *)imem_pointer, 0, 4);
    return 0;
}
__export __global __emem int errors = 0;

int main(void){
    if(ctx() == 0){
        // if(test_malloc() != 0){
        //     errors++;
        // }
        if(test_movement() != 0){
            errors++;
        }
        return errors;
    }
    return 0;
}