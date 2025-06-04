#include <nfp.h>
#include <nfp_intrinsic.h>
#include <stdint.h>
#include <nfp/me.h>

#define CTM_SIZE 262144
#define IMEM_SIZE 4194304 

#define EMEM0_SIZE 100000
#define EMEM1_SIZE 10000

__export __global __mem40 __emem_n(0) int ctm32_times[CTM_SIZE];
__export __global __mem40 __emem_n(0) int ctm33_times[CTM_SIZE];
__export __global __mem40 __emem_n(0) int ctm34_times[CTM_SIZE];
__export __global __mem40 __emem_n(0) int ctm35_times[CTM_SIZE];
__export __global __mem40 __emem_n(0) int ctm36_times[CTM_SIZE];
__export __global __mem40 __emem_n(0) int imem_times[IMEM_SIZE];
__export __global __mem40 __emem int emem0_times[EMEM0_SIZE];
__export __global __mem40 __emem_n(0) int emem1_times[EMEM1_SIZE];

volatile __addr40 __ctm_n(32) char ctm32[CTM_SIZE];
volatile __addr40 __ctm_n(33) char ctm33[CTM_SIZE];
volatile __ctm_n(34) char ctm34[CTM_SIZE];
volatile __ctm_n(35) char ctm35[CTM_SIZE];
volatile __ctm_n(36) char ctm36[CTM_SIZE];

volatile __imem char imem[IMEM_SIZE];
// volatile __declspec(emem0.emem_cache) char emem0[EMEM0_SIZE];
// volatile __declspec(emem1.emem_cache) char emem1[EMEM1_SIZE];
volatile __declspec(emem0) char emem0[EMEM0_SIZE];
volatile __declspec(emem1) char emem1[EMEM1_SIZE];


uint16_t time_write(__addr40 char *byte, char value){   
    SIGNAL my_signal;
    __gpr uint32_t begin, end;
    uint32_t address_high = ((uint64_t) byte >> 8) & 0xff000000;
    uint32_t address_low = byte;
    __xwrite int val = value;

    __asm{
        local_csr_rd[local_csr_profile_count]
        immed[begin, 0]
        mem[write8_le, val, address_high, <<8, address_low, 1], ctx_swap[my_signal]
        local_csr_rd[local_csr_profile_count]
        immed[end, 0]
    }
    
    //__asm mem[write8_le, val, address_high, <<8, address_low, 1], ctx_swap[my_signal];
    //return timestamp_stop(begin);
    return end - begin;
}

uint16_t time_read(__addr40 char *byte){   
    SIGNAL my_signal;
    __gpr uint32_t begin, end;
    uint32_t address_high = ((uint64_t) byte >> 8) & 0xff000000;
    uint32_t address_low = byte;
    __xread int val;

    __asm{
        local_csr_rd[local_csr_profile_count]
        immed[begin, 0]
        mem[read8, val, address_high, <<8, address_low, 1], ctx_swap[my_signal];
        local_csr_rd[local_csr_profile_count]
        immed[end, 0]
    }
    
    return end - begin;
}

uint16_t time_wr(__addr40 char *byte, char value){
    SIGNAL my_signal;
    __gpr uint32_t begin, end;
    uint32_t address_high = ((uint64_t) byte >> 8) & 0xff000000;
    uint32_t address_low = byte;
    __xwrite int wval = value;
    __xread int rval;
    
    __asm{
        local_csr_rd[local_csr_profile_count]
        immed[begin, 0]
        mem[write8_le, wval, address_high, <<8, address_low, 1], ctx_swap[my_signal]
        mem[read8, rval, address_high, <<8, address_low, 1], ctx_swap[my_signal]
        local_csr_rd[local_csr_profile_count]
        immed[end, 0]
    }

    return end - begin;
}

void ctm32_time(char operation){
    char to_write = 0;
    uint64_t i;

    for(i = 0; i < CTM_SIZE; i++){
        __addr40 char *off = (__addr40 char *)(ctm32 + i);
        ctm32_times[i] = time_write(off, to_write++);
    }

    if(operation){
        //read op
        for(i = 0; i < CTM_SIZE; i++){
            __addr40 char *off = (__addr40 char *)(ctm32 + i);
            ctm32_times[i] = time_read(off);
        }
    }
}

void ctm33_time(char operation){
    char to_write = 0;
    uint64_t i;

    for(i = 0; i < CTM_SIZE; i++){
        __addr40 char *off = (__addr40 char *)(ctm33 + i);
        ctm33_times[i] = time_write(off, to_write++);
    }

    if(operation){
        //read op
        for(i = 0; i < CTM_SIZE; i++){
            __addr40 char *off = (__addr40 char *)(ctm33 + i);
            ctm33_times[i] = time_read(off);
        }
    }
}

void ctm34_time(char operation){
    char to_write = 0;
    uint64_t i;

    for(i = 0; i < CTM_SIZE; i++){
        __addr40 char *off = (__addr40 char *)(ctm34 + i);
        ctm34_times[i] = time_write(off, to_write++);
    }

    if(operation){
        //read op
        for(i = 0; i < CTM_SIZE; i++){
            __addr40 char *off = (__addr40 char *)(ctm34 + i);
            ctm34_times[i] = time_read(off);
        }
    }
}

void ctm35_time(char operation){
    char to_write = 0;
    uint64_t i;

    for(i = 0; i < CTM_SIZE; i++){
        __addr40 char *off = (__addr40 char *)(ctm35 + i);
        ctm35_times[i] = time_write(off, to_write++);
    }

    if(operation){
        //read op
        for(i = 0; i < CTM_SIZE; i++){
            __addr40 char *off = (__addr40 char *)(ctm35 + i);
            ctm35_times[i] = time_read(off);
        }
    }
}

void ctm36_time(char operation){
    char to_write = 0;
    uint64_t i;

    for(i = 0; i < CTM_SIZE; i++){
        __addr40 char *off = (__addr40 char *)(ctm36 + i);
        ctm36_times[i] = time_write(off, to_write++);
    }

    if(operation){
        //read op
        for(i = 0; i < CTM_SIZE; i++){
            __addr40 char *off = (__addr40 char *)(ctm36 + i);
            ctm36_times[i] = time_read(off);
        }
    }
}

void imem_time(char operation){
    char to_write = 0;
    uint64_t i;

    for(i = 0; i < IMEM_SIZE; i++){
        __addr40 char *off = (__addr40 char *)(imem + i);
        imem_times[i] = time_write(off, to_write++);
    }

    if(operation){
        //read op
        for(i = 0; i < IMEM_SIZE; i++){
            __addr40 char *off = (__addr40 char *)(imem + i);
            imem_times[i] = time_read(off);
        }
    }
}

void emem1_time(char operation){
    char to_write = 0;
    uint64_t i;

    for(i = 0; i < EMEM1_SIZE; i++){
        __addr40 char *off = (__addr40 char *)(emem1 + i);
        emem1_times[i] = time_write(off, to_write++);
    }

    if(operation){
        //read op
        for(i = 0; i < EMEM1_SIZE; i++){
            __addr40 char *off = (__addr40 char *)(emem1 + i);
            emem1_times[i] = time_read(off);
        }
    }
}

void emem0_time(char operation){
    char to_write = 0;
    uint64_t i;

    for(i = 0; i < EMEM0_SIZE; i++){
        __addr40 char *off = (__addr40 char *)(emem0 + i);
        emem0_times[i] = time_write(off, to_write++);
    }

    if(operation){
        //read op
        for(i = 0; i < EMEM0_SIZE; i++){
            __addr40 char *off = (__addr40 char *)(emem0 + i);
            emem0_times[i] = time_read(off);
        }
    }
}

void time_op(char operation, __addr40 char *mem, uint64_t ops, __volatile __mem40 int *times){
    char to_write = 0;
    uint64_t i;
    switch(operation){
        case 0:
            //write
            __asm local_csr_wr[local_csr_mailbox1, 1];
            for(i = 0; i < ops; i++){
                __addr40 char *off = (__addr40 char *)(mem + i);
                times[i] = time_write(off, to_write++);
            }
            break;
        case 1:
            //read
            for(i = 0; i < ops; i++){
                __addr40 char *off = (__addr40 char *)(mem + i);
                times[i] = time_write(off, to_write++);
            } 
            for(i = 0; i < ops; i++){
                __addr40 char *off = (__addr40 char *)(mem + i);
                times[i] = time_read(off);
            } 
            break;
        case 2:
            //write then read
            for(i = 0; i < ops; i++){
                __addr40 char *off = (__addr40 char *)(mem + i);
                times[i] = time_wr(off, to_write++);
            } 
            break;
        default:
            return;
    }
}

int main(void){
    //ctm32_time(0);
    // ctm33_time(0);
    // ctm34_time(0);
    // ctm35_time(0);
    // ctm36_time(0);
    // imem_time(0);
    // emem0_time(0);
    // emem1_time(0); 

    char operation = 2;

    time_op(operation, (__addr40 char *)ctm32, CTM_SIZE, ctm32_times);
    time_op(operation, (__addr40 char *)ctm33, CTM_SIZE, ctm33_times);
    time_op(operation, (__addr40 char *)ctm34, CTM_SIZE, ctm34_times);  
    time_op(operation, (__addr40 char *)ctm35, CTM_SIZE, ctm35_times);
    time_op(operation, (__addr40 char *)ctm36, CTM_SIZE, ctm36_times);
    time_op(operation, (__addr40 char *)imem, IMEM_SIZE, imem_times);
    time_op(operation, (__addr40 char *)emem0, EMEM0_SIZE, emem0_times);
    time_op(operation, (__addr40 char *)emem1, EMEM1_SIZE, emem1_times);
    __asm HALT
}

