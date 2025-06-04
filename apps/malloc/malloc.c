#include <nfp.h>
#include "malloc.h"

#define EMEM0_HEAP_SIZE 2097152
#define EMEM1_HEAP_SIZE 1048576
#define IMEM_HEAP_SIZE 1048576
#define CTM33_HEAP_SIZE 65536

__export __global __emem_n(0) char emem0_heap[EMEM0_HEAP_SIZE];
__export __global __addr40 __emem char *emem0_free = emem0_heap;

__export __global __emem_n(1) char emem1_heap[EMEM1_HEAP_SIZE];
__export __global __addr40 __emem char *emem1_free = emem1_heap;

__export __global __imem char imem_heap[IMEM_HEAP_SIZE];
__export __global __addr40 __imem char *imem_free = imem_heap; 

__export __global __ctm_n(33) char ctm33_heap[CTM33_HEAP_SIZE];
__export __global __addr40 __ctm char *ctm33_free = ctm33_heap; 

__addr40 __ctm void *pick_ctm33(unsigned int size){
    return (__addr40 __ctm void *) ctm33_free;
}

__addr40 __imem void *pick_imem(unsigned int size){
    return (__addr40 __imem void *) imem_free;
}

__addr40 __emem void *pick_emem0(unsigned int size){
    return (__addr40 __emem void *) emem0_free;
}

__addr40 __emem void *pick_emem1(unsigned int size){
    return (__addr40 __emem void *) emem1_free;
}

__addr40 void *malloc(unsigned int size){
    return (__addr40 void *) pick_ctm33(size);    
}





