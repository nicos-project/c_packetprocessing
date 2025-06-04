#include <nfp.h>
#include <nfp/mem_atomic.h>
#include <nfp/mem_bulk.h>
#define FLOW_STORAGE_SIZE     321

typedef enum { 
    FSM_0 = 0,  // Initial
    FSM_S = 1,  // Received SYN
    FSM_E = 2,  // Established
    FSM_F = 3,  // Received FIN
    FSM_W = 4,  // Waiting for final ACK
    FSM_C = 5   // Closed
} tcp_fsm_t;

typedef __declspec(packed) struct {
    tcp_fsm_t FSM:3;
    uint8_t active:1;
    uint8_t eseq_valid:1;
} flow_ctrl_bits_T;

typedef struct flow_bucket_value_Type {
    uint32_t eseq;         // expected sequence number
    uint16_t oooqLen;      // number of packets in the ooo pool
    uint16_t cs;           // saved dfa state
} flow_bucket_value_T;

// the flow hash table
typedef struct flow_ht_entry_Type {
    uint32_t key[3];       // sip, dip, sport|dport
    flow_bucket_value_T value;
    uint16_t partition;    // slice of memory used for packet storage
    uint16_t next_loc;     // linked list ptr
    flow_ctrl_bits_T ctrl_bits; 
} flow_ht_entry_T;

__shared __export __addr40 __mem flow_ht_entry_T flow_ht[FLOW_STORAGE_SIZE];

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
    DEBUG(0xdeadbeef, sizeof(flow_ctrl_bits_T), sizeof(flow_bucket_value_T), sizeof(flow_ht_entry_T));
}