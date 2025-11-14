#include <nfp.h>
#include <nfp6000/nfp_me.h>
#include <pkt/pkt.h>
#include <stdint.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <std/hash.h>
#include <nfp/me.h>
#include <nfp/mem_lkup.h>
#include <nfp/mem_bulk.h>
#include <std/reg_utils.h>

#include "config.h"
#include "steer.h"
#include "lb.h"

// Global load balancer state
__declspec(LB_TABLE_MEM_TYPE export scope(global)) struct lb_table_bucket lb_table[LB_TABLE_NUM_BUCKETS];
__declspec(LB_TABLE_MEM_TYPE export scope(global) aligned(64)) int lb_per_bucket_sem[LB_TABLE_NUM_BUCKETS];
__declspec(LB_TABLE_MEM_TYPE export scope(global)) struct lb_reverse_entry lb_reverse_table[CLIENT_PORT_POOL_SIZE];
__declspec(LB_TABLE_MEM_TYPE export scope(global)) struct backend_info backends[MAX_BACKENDS];
__declspec(LB_TABLE_MEM_TYPE export scope(global) aligned(64)) struct backend_load backend_loads[MAX_BACKENDS];
__declspec(LB_TABLE_MEM_TYPE export scope(global) aligned(64)) int backend_load_sem;

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

// Find the least loaded backend server
__intrinsic uint8_t select_least_loaded_backend(void) {
    __gpr uint8_t best_backend = 0;
#ifdef LOAD_METRIC_BYTES
    __gpr uint64_t min_load = backend_loads[0].total_bytes;
    __gpr uint8_t i;
    
    for (i = 1; i < ACTIVE_BACKENDS; i++) {
        if (backends[i].active && backend_loads[i].total_bytes < min_load) {
            min_load = backend_loads[i].total_bytes;
            best_backend = i;
        }
    }
#endif

#ifdef LOAD_METRIC_CONNECTIONS
    __gpr uint32_t min_connections = backend_loads[0].active_connections;
    __gpr uint8_t i;
    
    for (i = 1; i < ACTIVE_BACKENDS; i++) {
        if (backends[i].active && backend_loads[i].active_connections < min_connections) {
            min_connections = backend_loads[i].active_connections;
            best_backend = i;
        }
    }
#endif

#ifdef LOAD_METRIC_EWMA
    __gpr uint64_t min_ewma = backend_loads[0].ewma_load;
    __gpr uint8_t i;
    
    for (i = 1; i < ACTIVE_BACKENDS; i++) {
        if (backends[i].active && backend_loads[i].ewma_load < min_ewma) {
            min_ewma = backend_loads[i].ewma_load;
            best_backend = i;
        }
    }
#endif

    return best_backend;
}

// Update load for a backend
__intrinsic void update_backend_load(uint8_t backend_id, uint32_t pkt_len) {
#ifdef LOAD_METRIC_BYTES
    backend_loads[backend_id].total_bytes += pkt_len;
#endif

#ifdef LOAD_METRIC_CONNECTIONS
    // Connection count updated separately on SYN/FIN
#endif

#ifdef LOAD_METRIC_EWMA
    // EWMA update: new_ewma = alpha * current + (1-alpha) * old_ewma
    // Using shift for division: alpha = 1/8
    uint64_t delta = pkt_len - (backend_loads[backend_id].ewma_load >> EWMA_DECAY_SHIFT);
    backend_loads[backend_id].ewma_load += delta;
#endif
}

// Find existing connection in load balancer table
__intrinsic int8_t find_in_lb_table(uint32_t hash_value, uint32_t table_idx) {
    __gpr uint32_t cur_idx = 0;
    __gpr int8_t backend_id = -1;
    
    while (cur_idx < LB_TABLE_MAX_ENTRIES_PER_BUCKET) {
        if (lb_table[table_idx].entry[cur_idx].four_tuple_hash == hash_value &&
            lb_table[table_idx].entry[cur_idx].valid) {
            backend_id = lb_table[table_idx].entry[cur_idx].backend_id;
            break;
        }
        else if (lb_table[table_idx].entry[cur_idx].four_tuple_hash == 0) {
            // Empty entry, no match found
            break;
        }
        cur_idx++;
    }
    return backend_id;
}

// Remove connection from load balancer table
__intrinsic void remove_from_lb_table(uint32_t hash_value, uint32_t table_idx) {
    __gpr uint32_t cur_idx = 0;
    
    while (cur_idx < LB_TABLE_MAX_ENTRIES_PER_BUCKET) {
        if (lb_table[table_idx].entry[cur_idx].four_tuple_hash == hash_value &&
            lb_table[table_idx].entry[cur_idx].valid) {
            lb_table[table_idx].entry[cur_idx].valid = 0;
            lb_table[table_idx].entry[cur_idx].four_tuple_hash = 0;
            lb_table[table_idx].bucket_count--;
            break;
        }
        cur_idx++;
    }
}

int main(void)
{
    // Load balancer main loop
    __gpr struct work_t work;
    __gpr struct pkt_ms_info msi;
    __gpr unsigned int type, island, pnum, plen, seqr, seq;
    __gpr unsigned int rnum, raddr_hi;
    __gpr uint8_t pkt_off = PKT_NBI_OFFSET + MAC_PREPEND_BYTES;
    __gpr uint8_t rx_port;
    __xread  struct work_t work_read;

    // Load balancer specific variables
    __gpr int i, j;
    __gpr uint32_t from_client;  // 1 if from client, 0 if from backend
    __gpr uint32_t hash_value;
    __gpr int8_t backend_id = -1;
    __gpr uint16_t client_port_idx;
    __xread struct nbi_meta_catamaran nbi_meta;
    __xread struct nbi_meta_pkt_info *pi = &nbi_meta.pkt_info;
    __declspec(ctm shared) __mem40 char *pbuf;
    __declspec(ctm shared) __mem40 struct ip4_hdr *ip_hdr;
    __declspec(ctm shared) __mem40 struct tcp_hdr *tcp_hdr;
    __declspec(ctm shared) __mem40 uint16_t *l4_src_port;
    __declspec(ctm shared) __mem40 uint16_t *l4_dst_port;
    __declspec(ctm shared) __mem40 uint32_t *data;

    // Table management
    __gpr uint32_t table_idx, bucket_idx;
    SIGNAL work_sig;

    island = __ISLAND;

    // Initialize work queue based on island
    if (island == 33) {
        rnum = MEM_RING_GET_NUM(flow_ring_0);
        raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_0);
    }
    else if (island == 34) {
        rnum = MEM_RING_GET_NUM(flow_ring_1);
        raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_1);
    }
    else if (island == 35) {
        rnum = MEM_RING_GET_NUM(flow_ring_2);
        raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_2);
    }
    else if (island == 36) {
        rnum = MEM_RING_GET_NUM(flow_ring_3);
        raddr_hi = MEM_RING_GET_MEMADDR(flow_ring_3);
    }

    // Initialize backend servers
    backends[0].ip = BACKEND_0_IP;
    backends[0].port = BACKEND_PORT;
    backends[0].active = 1;
    
    backends[1].ip = BACKEND_1_IP;
    backends[1].port = BACKEND_PORT;
    backends[1].active = 1;
    
    backends[2].ip = BACKEND_2_IP;
    backends[2].port = BACKEND_PORT;
    backends[2].active = 1;
    
    backends[3].ip = BACKEND_3_IP;
    backends[3].port = BACKEND_PORT;
    backends[3].active = 1;

    // Initialize remaining backends as inactive
    for (i = ACTIVE_BACKENDS; i < MAX_BACKENDS; i++) {
        backends[i].active = 0;
    }

    // Initialize load tracking
    backend_load_sem = 1;
    for (i = 0; i < MAX_BACKENDS; i++) {
#ifdef LOAD_METRIC_BYTES
        backend_loads[i].total_bytes = 0;
#endif
#ifdef LOAD_METRIC_CONNECTIONS
        backend_loads[i].active_connections = 0;
#endif
#ifdef LOAD_METRIC_EWMA
        backend_loads[i].ewma_load = 0;
#endif
    }

    // Initialize connection table
    for (i = 0; i < LB_TABLE_NUM_BUCKETS; i++) {
        lb_table[i].bucket_count = 0;
        lb_per_bucket_sem[i] = 1;
        for (j = 0; j < LB_TABLE_MAX_ENTRIES_PER_BUCKET; j++) {
            lb_table[i].entry[j].four_tuple_hash = 0;
            lb_table[i].entry[j].valid = 0;
        }
    }

    // Initialize reverse lookup table
    for (i = 0; i < CLIENT_PORT_POOL_SIZE; i++) {
        lb_reverse_table[i].word64 = 0;
    }

    // Main packet processing loop
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
        from_client = work.lan_or_wan;  // Reusing lan_or_wan field

        pbuf = pkt_ctm_ptr40(island, pnum, 0);

        ip_hdr = (__mem40 struct ip4_hdr *)(pbuf + pkt_off + sizeof(struct eth_hdr));

        tcp_hdr = (__mem40 struct tcp_hdr *)(pbuf + pkt_off
                                                  + sizeof(struct eth_hdr)
                                                  + sizeof(struct ip4_hdr));

        l4_src_port  = (__mem40 uint16_t *)(&tcp_hdr->sport);
        l4_dst_port  = (__mem40 uint16_t *)(&tcp_hdr->dport);

        data = (__mem40 uint32_t *)(pbuf + pkt_off
                                         + sizeof(struct eth_hdr)
                                         + sizeof(struct ip4_hdr)
                                         + sizeof(struct tcp_hdr));

        if (from_client == 1) {
            // Traffic from client to load balancer (virtual IP)
            
            hash_value = work.hash;
            table_idx = hash_value & LB_TABLE_ID_MASK;

            if (tcp_hdr->flags & NET_TCP_FLAG_SYN) {
                // New connection - select backend using load balancing
                semaphore_down(&backend_load_sem);
                backend_id = select_least_loaded_backend();
                semaphore_up(&backend_load_sem);

                // Add to connection table
                semaphore_down(&lb_per_bucket_sem[table_idx]);
                
                bucket_idx = lb_table[table_idx].bucket_count;
                if (bucket_idx < LB_TABLE_MAX_ENTRIES_PER_BUCKET) {
                    lb_table[table_idx].entry[bucket_idx].four_tuple_hash = hash_value;
                    lb_table[table_idx].entry[bucket_idx].backend_id = backend_id;
                    lb_table[table_idx].entry[bucket_idx].valid = 1;
                    lb_table[table_idx].bucket_count++;

                    // Calculate client port for tracking
                    client_port_idx = (table_idx * LB_TABLE_MAX_ENTRIES_PER_BUCKET + bucket_idx) % CLIENT_PORT_POOL_SIZE;
                    
                    // Update reverse lookup table
                    lb_reverse_table[client_port_idx].client_ip = ip_hdr->src;
                    lb_reverse_table[client_port_idx].client_port = *l4_src_port;
                    lb_reverse_table[client_port_idx].backend_id = backend_id;
                    lb_reverse_table[client_port_idx].valid = 1;

                    // Update connection count
#ifdef LOAD_METRIC_CONNECTIONS
                    semaphore_down(&backend_load_sem);
                    backend_loads[backend_id].active_connections++;
                    semaphore_up(&backend_load_sem);
#endif

                    // Debug info
                    *data = 0xAAAA0000 | backend_id;
                }
                
                semaphore_up(&lb_per_bucket_sem[table_idx]);
            }
            else {
                // Existing connection - lookup backend
                backend_id = find_in_lb_table(hash_value, table_idx);
                if (backend_id == -1) {
                    // Connection not found - this shouldn't happen
                    *data = 0xDEADBEEF;
                }
            }

            // Handle FIN - connection teardown
            if (tcp_hdr->flags & NET_TCP_FLAG_FIN) {
#ifdef LOAD_METRIC_CONNECTIONS
                if (backend_id >= 0) {
                    semaphore_down(&backend_load_sem);
                    if (backend_loads[backend_id].active_connections > 0) {
                        backend_loads[backend_id].active_connections--;
                    }
                    semaphore_up(&backend_load_sem);
                }
#endif
                // Remove from connection table
                semaphore_down(&lb_per_bucket_sem[table_idx]);
                remove_from_lb_table(hash_value, table_idx);
                semaphore_up(&lb_per_bucket_sem[table_idx]);
            }

            if (backend_id >= 0) {
                // Update load statistics
                semaphore_down(&backend_load_sem);
                update_backend_load(backend_id, plen);
                semaphore_up(&backend_load_sem);

                // Rewrite packet to backend server
                ip_hdr->dst = backends[backend_id].ip;
                *l4_dst_port = backends[backend_id].port;
            }
        }
        else {
            // Traffic from backend to client
            // Use source port to lookup original client info
            
            // Simple port-based reverse lookup
            // In production, you'd want a more robust mapping
            client_port_idx = *l4_src_port % CLIENT_PORT_POOL_SIZE;
            
            if (lb_reverse_table[client_port_idx].valid) {
                // Restore original client IP and port
                ip_hdr->dst = lb_reverse_table[client_port_idx].client_ip;
                *l4_dst_port = lb_reverse_table[client_port_idx].client_port;
                ip_hdr->src = VIRTUAL_IP;
            }
            else {
                // Reverse entry not found
                *data = 0xBADBAD00;
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

