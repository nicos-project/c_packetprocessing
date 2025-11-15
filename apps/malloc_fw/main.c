/**
 * @file: firewall.c
 * @brief: Connection table based firewall. Allows connections from the internal
 * network (LAN) and blocks unknown connections on the WAN. Simple IP source
 * based check to filter LAN and WAN traffic.
 *
 * */
#include <nfp.h>
#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_lkup.h>
#include <nfp/mem_bulk.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <std/reg_utils.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "config.h"
#include "steer.h"
#include "dependencies/hash-table/flow_table.h"
#include "dependencies/hash-table/dependencies/libmalloc/malloc.h"
#include "dependencies/hash-table/dependencies/libmalloc/dependencies/mem40_barrier/mem40_barrier.h"
#include "dependencies/hash-table/dependencies/mem40_mutex/mem40_mutex.h"

#define CONN_TABLE_NUM_BUCKETS 100
#define CONN_TABLE_MAX_KEYS_PER_BUCKET 4
struct conn_table_bucket {
    // Each bucket basically holds four keys
    uint32_t four_tuple_hash_entry[CONN_TABLE_MAX_KEYS_PER_BUCKET];
};

// Will aligning this help?
__declspec(imem export scope(global)) struct conn_table_bucket conn_table[CONN_TABLE_NUM_BUCKETS];
__export __global __ctm_n(33) flow_table_t i33_flow_table;
__export __global __ctm_n(34) flow_table_t i34_flow_table;
__export __global __ctm_n(35) flow_table_t i35_flow_table;
__export __global __ctm_n(36) flow_table_t i36_flow_table;
/**
 * We can cache a local copy of the handle to island flow table because
 * the data pointed to in this struct will be anchored to island CTM. This means
 * the pointers in the struct will not move.
 */
__shared __lmem flow_table_t island_flow_table;
__gpr unsigned int rnum, raddr_hi;

//initialization variables
__export __global __align64 __emem uint32_t firewall_initialization_lock;
__export __global __align64 __emem uint32_t initialize_barrier_arrive_num = NUM_THREADS; //This will be wrong when we add movement
__export __global __align64 __emem uint32_t initialize_barrier_leave_num = 0;
barrier_t firewall_barrier = {
    NUM_THREADS,
    (__mem40 uint32_t *)&initialize_barrier_arrive_num,
    (__mem40 uint32_t *)&initialize_barrier_leave_num
};

void semaphore_down(volatile __declspec(mem addr40) void * addr)
{
    /* semaphore "DOWN" = claim = wait */
    unsigned int addr_hi, addr_lo;
    __declspec(read_write_reg) int xfer;
    SIGNAL_PAIR my_signal_pair;

    addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)addr & 0xffffffff;

    do {
        xfer = 1;
        __asm {
            mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1], \
                sig_done[my_signal_pair];
            ctx_arb[my_signal_pair]
        }
    } while (xfer == 0);
}

void semaphore_up(volatile __declspec(mem addr40) void * addr)
{
    /* semaphore "UP" = release = signal */
    unsigned int addr_hi, addr_lo;
    __declspec(read_write_reg) int xfer;

    addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)addr & 0xffffffff;

    __asm {
        mem[incr, --, addr_hi, <<8, addr_lo, 1];
    }
}

// Global connection state
// We split this between the different islands: each island serves a unique set of flows due to
// the steering island assigning flows based on the four tuple hash. Each island has 8 MEs serving
// a set of flows, and more than one ME may end up serving a single flow. That is why we need an island
// scope lock on the ct_bucket_count and conn_table data structures.
// Each bucket has its own lock in imem for fine-grained concurrency control.
__declspec(imem export scope(island)) int ct_sem[CONN_TABLE_NUM_BUCKETS];
__declspec(imem export scope(global)) uint8_t ct_bucket_count[CONN_TABLE_NUM_BUCKETS];

__intrinsic uint8_t find_in_conn_table(uint32_t hash_value, uint32_t table_idx) {
    __gpr uint32_t cur_idx = 0;
    __gpr uint8_t present_in_conn_table = 0;
    while (cur_idx < CONN_TABLE_MAX_KEYS_PER_BUCKET) {
        if (conn_table[table_idx].four_tuple_hash_entry[cur_idx] == hash_value) {
            present_in_conn_table = 1;
            break;
        }
        else if (conn_table[table_idx].four_tuple_hash_entry[cur_idx] == 0) {
            // we initialize all entries to zero in the start
            // and add them sequentially, so if we found a 0 entry
            // we can break since there are no entries further down
            break;
        }
        cur_idx++;
    }
    return present_in_conn_table;
}

void initialize(){
    int island = __ISLAND;
    init_malloc();

    if(try_lock((__mem40 uint32_t *)&firewall_initialization_lock)){
        //only one thread
        i33_flow_table = ft_constructor(CONN_TABLE_NUM_BUCKETS, ANCHORED_CTM33);
        i34_flow_table = ft_constructor(CONN_TABLE_NUM_BUCKETS, ANCHORED_CTM34);
        i35_flow_table = ft_constructor(CONN_TABLE_NUM_BUCKETS, ANCHORED_CTM35);
        i36_flow_table = ft_constructor(CONN_TABLE_NUM_BUCKETS, ANCHORED_CTM36);
    }

    //wait for all island flow tables to be constructed
    synch(firewall_barrier);

    if(__ctx() == 0){
        if (island == 33) {
            rnum = MEM_RING_GET_NUM(flow_ring_0);
            raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_0);
            island_flow_table = i33_flow_table;
        }
        else if (island == 34) {
            rnum = MEM_RING_GET_NUM(flow_ring_1);
            raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_1);
            island_flow_table = i34_flow_table;
        }
        else if (island == 35) {
            rnum = MEM_RING_GET_NUM(flow_ring_2);
            raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_2);
            island_flow_table = i35_flow_table;
        }
        else if (island == 36) {
            rnum = MEM_RING_GET_NUM(flow_ring_3);
            raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_3);
            island_flow_table = i36_flow_table;
        } 
    }

    /**
     * Wait for ctx 0 of this ME to get the local copy of the flow table handle
     */
    synch(firewall_barrier);
}

int main(void)
{
    __gpr struct work_t work;
    __gpr struct pkt_ms_info msi;
    __gpr unsigned int type, island, pnum, plen, seqr, seq;
    __gpr uint8_t pkt_off = PKT_NBI_OFFSET + MAC_PREPEND_BYTES;
    __gpr uint8_t rx_port;
    __xread  struct work_t work_read;
    SIGNAL work_sig;

    __gpr uint32_t lan_or_wan;
    __gpr uint32_t hash_value;
    __gpr int i, j;
    __gpr uint32_t ip_tmp;
    __gpr uint16_t port_tmp;

    /**
     * You dont want this pointer (or the tcp_hdr pointer) to be shared.
     * This would mean that all threads on the ME see the same pointer and
     * are trying to use it at the same time.
     */
    __declspec(ctm) __mem40 char *pbuf;
    
    __gpr ipv4_5_tuple_t tup;   
    __lmem char data_buff[DATA_SIZE];
    __declspec(ctm) __mem40 struct tcp_hdr *tcp_hdr;
    __gpr uint8_t flags;

    // __declspec(ctm shared) __mem40 struct ip4_hdr *ip_hdr;
    // __declspec(ctm shared) __mem40 uint16_t *l4_src_port;
    // __declspec(ctm shared) __mem40 uint16_t *l4_dst_port;
    // __declspec(ctm shared) __mem40 uint32_t *data;

    // Connection table stuff
    __gpr uint8_t present_in_conn_table;
    
    initialize();
    for (;;) {
        __mem_workq_add_thread(rnum, raddr_hi,
                        &work_read,
                        sizeof(struct work_t), sizeof(struct work_t),
                        sig_done, &work_sig);
        __wait_for_all(&work_sig);

        work = work_read;
        island = work.isl;
        pnum = work.pnum;
        plen = work.plen;
        seqr = work.seqr;
        seq = work.seq;
        rx_port = work.rx_port;
        lan_or_wan = work.lan_or_wan;
        tup = work.five_tuple;
        
        pbuf = pkt_ctm_ptr40(island, pnum, 0);

        // ip_hdr = (__mem40 struct ip4_hdr *)(pbuf + pkt_off + sizeof(struct eth_hdr));

        tcp_hdr = (__mem40 struct tcp_hdr *)(pbuf + pkt_off
                                                    + sizeof(struct eth_hdr)
                                                    + sizeof(struct ip4_hdr));

        flags = tcp_hdr->flags;

        // l4_src_port  = (__mem40 uint16_t *)(&tcp_hdr->sport);

        // l4_dst_port  = (__mem40 uint16_t *)(&tcp_hdr->dport);

        // data = (__mem40 uint32_t *)(pbuf + pkt_off
        //                                     + sizeof(struct eth_hdr)
        //                                     + sizeof(struct ip4_hdr)
        //                                     + sizeof(struct tcp_hdr));

        if (lan_or_wan == 0) {
        //     /**
        //      * We start by checking if the flow is in the connection table
        //      * or not. We basically allow all connections on the LAN port
        //      *
        //      * Perform a lookup in the connection table and see if it is there 
        //     */ 

            if(flags & NET_TCP_FLAG_SYN) {  // SYN should be bit 1
                //insert flow to table with some data
                reg_zero(data_buff, DATA_SIZE);
                ft_insert(island_flow_table, tup, (char *) data_buff);
                tcp_hdr->flags = NET_TCP_FLAG_FIN;
            }
            else if(flags & NET_TCP_FLAG_FIN){
                //LAN side is closing the connection
                // if(ft_lookup(island_flow_table, tup, (char *) data_buff) == 0){
                //     //this packet is retrying to close the connection, let it through
                // }
                // else{
                //     //delete the flow entry for this 5 tuple
                //     ft_delete(island_flow_table, tup);
                // }
                ft_delete(island_flow_table, tup);
                tcp_hdr->flags = NET_TCP_FLAG_SYN;
            }
            else{
                //any other packet from LAN side can be forwarded without touching the flow table
            }
        }
        else {
            /**
             * WAN side packet
             */
            present_in_conn_table = ft_lookup(island_flow_table, tup, (char *) data_buff);
            
            if(present_in_conn_table || flags & NET_TCP_FLAG_FIN) {
                tcp_hdr->flags = NET_TCP_FLAG_SYN;
            //     //packet can be forwarded: part of ACL or responding to a fin

            //     // found
            //     // we only do useful stuff on the WAN port side with this
            //     // *data = hash_value;
            //     // *data = 0x2;
            //     // Uncomment to test with firewall-test.py
            //     // *data = 0xabcdef12;
            }
            else {
                tcp_hdr->flags = NET_TCP_FLAG_FIN;
            //     // we have a problem, someone is trying to intrude?
            //     // drop the packet
            //     // Uncomment to test with firewall-test.py
            //     // *data = 0xffffffff;
            //     // data += 1;
            //     // *data = hash_value;
            }
        }

        // Send the packet back
        pkt_mac_egress_cmd_write(pbuf, pkt_off, 1, 1);
        msi = pkt_msd_write(pbuf, pkt_off - 4);
        pkt_nbi_send(island,
                        pnum,
                        &msi,
                        plen - MAC_PREPEND_BYTES + 4,
                        0, // NBI is 0
                        PORT_TO_TMQ(rx_port), // same port as what we received it on
                        seqr, seq, PKT_CTM_SIZE_256);
    }
    return 0;
}

/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
