#include <nfp.h>
#include <nfp/cls.h>
#include <std/hash.h>
#include <stdint.h>

__volatile __emem uint64_t hash[100];

__volatile __cls char *mask;

int main(void){
    __xwrite int key[2];
    int i;
    
    cls_hash_init((__cls void *) mask, 8);
    
    for(i = 0; i < 100; i++){
        key[0] = i;
        key[1] = i - 1;
        hash[i] = cls_hash(&key, (__cls void *)mask, 8, __ctx());
    }

}