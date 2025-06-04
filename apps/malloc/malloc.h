#ifndef __MALLOC__
#define __MALLOC__

__addr40 void *malloc(unsigned int);

__addr40 __emem void *pick_emem0(unsigned int);
__addr40 __emem void *pick_emem1(unsigned int);
__addr40 __imem void *pick_imem(unsigned int);
__addr40 __ctm void *pick_ctm33(unsigned int);

#endif