#include <nfp.h>

typedef __packed struct stru{
    __mem40 int *arr;
    uint32_t size;
} my_struct_t;

__export __global __mem40 __emem_n(0) int old[10] = {1,2,3,4,5};
__export __global __emem_n(0) my_struct_t my_struct = {
	(__mem40 int *)old,
	10
};


__declspec(ctm) int new[sizeof(old)/sizeof(int)];

int main(void)
{
        if (__ctx() == 0)
        {
                int i, size;
                size = sizeof(old)/sizeof(int);
                for (i=0; i < size; i++)
                {
                        new[i] = old[size - i - 1];
                }
        }
        return 0;
}
