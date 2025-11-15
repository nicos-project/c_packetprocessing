#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "src/config.h"
#include "src/network.h"
#include "src/flow_table.h"
#include "src/test_cases.h"

// Global flow table to track inserted flows
FlowTable local_table;

int main(int argc, char* argv[]) {
    (void)argc; // Unused parameter
    (void)argv; // Unused parameter

    int sockfd, ifindex;
    TestStats stats = {0, 0, 0}; // Initialize test statistics

    printf("========================================\n");
    printf("NIC Firewall Comprehensive Test Suite\n");
    printf("========================================\n");
    printf("Interface: %s\n", INTERFACE);
    printf("\n");

    // Create raw socket
    sockfd = create_raw_socket(INTERFACE, &ifindex);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to create raw socket (need root privileges)\n");
        return 1;
    }

    // Set promiscuous mode
    if (set_promiscuous_mode(sockfd, ifindex) < 0) {
        close(sockfd);
        return 1;
    }

    // Bind to interface
    if (bind_to_interface(sockfd, ifindex) < 0) {
        close(sockfd);
        return 1;
    }

    printf("Socket configured successfully\n");

    // Run all test cases
    printf("\n");
    printf("========================================\n");
    printf("Running Test Suite\n");
    printf("========================================\n");

    // Test Case 1: Basic INSERT-LOOKUP-DELETE
    test_case_1_basic_insert_lookup_delete(sockfd, ifindex, local_table, stats);

    // Test Case 2: Multiple concurrent flows
    test_case_2_multiple_flows(sockfd, ifindex, local_table, stats);

    // Test Case 3: Duplicate INSERT
    test_case_3_duplicate_insert(sockfd, ifindex, local_table, stats);

    // Test Case 4: DELETE non-existent flow
    test_case_4_delete_nonexistent(sockfd, ifindex, local_table, stats);

    // Test Case 5: LOOKUP non-existent flow
    test_case_5_lookup_nonexistent(sockfd, ifindex, local_table, stats);

    // Test Case 6: Different source ports
    test_case_6_different_src_ports(sockfd, ifindex, local_table, stats);

    // Test Case 7: Different destination ports
    test_case_7_different_dst_ports(sockfd, ifindex, local_table, stats);

    // Test Case 8: Interleaved INSERT and DELETE
    test_case_8_interleaved_ops(sockfd, ifindex, local_table, stats);

    // Test Case 9: Partial cleanup
    test_case_9_partial_cleanup(sockfd, ifindex, local_table, stats);

    // Test Case 10: Stress test
    test_case_10_stress_test(sockfd, ifindex, local_table, stats);

    // Test Case 11: Sequential port numbers
    test_case_11_sequential_ports(sockfd, ifindex, local_table, stats);

    // Test Case 12: Re-INSERT after DELETE
    test_case_12_reinsert_after_delete(sockfd, ifindex, local_table, stats);

    // Print final local table state
    printf("\n");
    printf("========================================\n");
    local_table.print_all();
    printf("========================================\n");

    // Print overall statistics
    print_test_stats(stats);

    close(sockfd);
    return (stats.failed > 0) ? 1 : 0;
}
