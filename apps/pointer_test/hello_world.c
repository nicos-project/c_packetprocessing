#include <nfp.h>
__shared __ctm_n(32) char ctm_array[64]; 
__shared __imem char imem_array[64];
__shared __emem_n(0) char emem0_array[64];
__shared __emem_n(1) char emem1_array[64];

typedef __packed struct{
    union{
        struct{
            uint32_t : 20;
            uint32_t size_class  : 4;   
            uint32_t resource_id : 8;
            uint32_t offset;
        };
        uint64_t raw;
    };
} ptr40_t;

__export __global __emem_n(0) __mem40 int *emem0_8b_sector_hdr;
__export __global __emem_n(0) ptr40_t emem0_8b_sector_hdr1;
__export __global __emem_n(0) uint64_t emem0_8b_sector_hdr2;


void test_pointer_manipulation(__addr40 void **ptr_to_ptr){
    unsigned int extra_bits = ((unsigned long long)*ptr_to_ptr & 0xffffff0000000000) >> 32;
    *ptr_to_ptr = 0xbeeA000000000;
    __asm{
        local_csr_wr[local_csr_mailbox2, extra_bits];
    } 
}

int main(void)
{
    if (__ctx() == 0)
    {
        unsigned int addr_high = ((unsigned long long) &emem1_array >> 8) & 0xff000000;
        unsigned int addr_low = &emem1_array;

        unsigned int offset = 0x000000;
        unsigned int island = 0x9c000000;

        __addr40 char *target = (unsigned long long)0xdeaf9c00000004;
        unsigned int target_high = ((unsigned long long) target >> 8) & 0xff000000;
        unsigned int target_low = target;
        unsigned int extra_bits;
        __declspec(write_reg) int val = 0xfe;
        __declspec(write_reg) int val2 = 0xff;
        SIGNAL my_signal;
        

        __asm{
            local_csr_wr[local_csr_mailbox0, addr_high];
            local_csr_wr[local_csr_mailbox1, addr_low];
            mem[write32, val, target_high, <<8, target_low, 1], ctx_swap[my_signal];
        }

        test_pointer_manipulation(&target);
        target_high = ((unsigned long long) target >> 8) & 0xff000000;
        target_low = target;
        extra_bits = ((unsigned long long)target & 0xffffff0000000000) >> 32;
        
        __asm{
            mem[write32, val2, target_high, <<8, target_low, 1], ctx_swap[my_signal];
            local_csr_wr[local_csr_mailbox3, extra_bits];
        } 
    }
    return 0;
}

