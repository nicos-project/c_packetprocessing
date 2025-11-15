#include "test_cases.h"
#include "pingpong.h"
#include <stdio.h>
#include <unistd.h>

// Helper function to print test case header
void print_test_header(const char* test_name, int test_number) {
    printf("\n");
    printf("========================================\n");
    printf("Test Case %d: %s\n", test_number, test_name);
    printf("========================================\n");
}

// Helper function to print test statistics
void print_test_stats(const TestStats& stats) {
    printf("\n");
    printf("========================================\n");
    printf("Overall Test Summary\n");
    printf("========================================\n");
    printf("Passed: %d/%d\n", stats.passed, stats.total);
    printf("Failed: %d/%d\n", stats.failed, stats.total);
    printf("Success Rate: %.1f%%\n", (stats.total > 0) ? (100.0 * stats.passed / stats.total) : 0.0);
    printf("========================================\n");
}

// Test Case 1: Basic INSERT-LOOKUP-DELETE sequence
bool test_case_1_basic_insert_lookup_delete(int sockfd, int ifindex,
                                             FlowTable& local_table, TestStats& stats) {
    print_test_header("Basic INSERT-LOOKUP-DELETE", 1);
    bool all_passed = true;

    // 1.1: INSERT
    printf("\n[1.1] INSERT flow 192.168.1.1:49000 -> 12.11.10.9:80\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 49000, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 1.2: LOOKUP (should find)
    printf("\n[1.2] LOOKUP inserted flow (should be found)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", 49000)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 1.3: DELETE
    printf("\n[1.3] DELETE flow 192.168.1.1:49000 -> 12.11.10.9:80\n");
    if (pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 49000, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 1.4: LOOKUP (should not find)
    printf("\n[1.4] LOOKUP deleted flow (should not be found)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", 49000)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    return all_passed;
}

// Test Case 2: Multiple concurrent flows
bool test_case_2_multiple_flows(int sockfd, int ifindex,
                                FlowTable& local_table, TestStats& stats) {
    print_test_header("Multiple Concurrent Flows", 2);
    bool all_passed = true;

    // 2.1-2.3: INSERT three flows
    printf("\n[2.1] INSERT flow 1: 192.168.1.1:49001 -> 12.11.10.9:80\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 49001, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    printf("\n[2.2] INSERT flow 2: 192.168.1.1:49002 -> 12.11.10.9:80\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 49002, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    printf("\n[2.3] INSERT flow 3: 192.168.1.1:49003 -> 12.11.10.9:443\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 49003, "12.11.10.9", 443)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 2.4-2.6: LOOKUP all three flows
    printf("\n[2.4] LOOKUP flow 1\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", 49001)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    printf("\n[2.5] LOOKUP flow 2\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", 49002)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    printf("\n[2.6] LOOKUP flow 3\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 443, "192.168.1.1", 49003)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // Cleanup: DELETE all flows
    printf("\n[Cleanup] Deleting all flows\n");
    pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 49001, "12.11.10.9", 80);
    usleep(100000);
    pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 49002, "12.11.10.9", 80);
    usleep(100000);
    pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 49003, "12.11.10.9", 443);
    usleep(100000);

    return all_passed;
}

// Test Case 3: Duplicate INSERT operations
bool test_case_3_duplicate_insert(int sockfd, int ifindex,
                                  FlowTable& local_table, TestStats& stats) {
    print_test_header("Duplicate INSERT Operations", 3);
    bool all_passed = true;

    // 3.1: First INSERT
    printf("\n[3.1] INSERT flow 192.168.1.1:50000 -> 12.11.10.9:8080\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 50000, "12.11.10.9", 8080)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 3.2: Duplicate INSERT (behavior may vary - might succeed or fail)
    printf("\n[3.2] Duplicate INSERT of same flow (observing behavior)\n");
    bool dup_result = pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 50000, "12.11.10.9", 8080);
    printf("  [INFO] Duplicate INSERT %s\n", dup_result ? "succeeded" : "failed");
    // Don't count this as pass/fail, just observe behavior
    usleep(100000);

    // 3.3: LOOKUP should still work
    printf("\n[3.3] LOOKUP flow after duplicate INSERT\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 8080, "192.168.1.1", 50000)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // Cleanup
    printf("\n[Cleanup] Deleting flow\n");
    pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 50000, "12.11.10.9", 8080);
    usleep(100000);

    return all_passed;
}

// Test Case 4: DELETE non-existent flow
bool test_case_4_delete_nonexistent(int sockfd, int ifindex,
                                    FlowTable& local_table, TestStats& stats) {
    (void)stats; // Unused - this test is observational only
    print_test_header("DELETE Non-existent Flow", 4);
    bool all_passed = true;

    // 4.1: DELETE flow that doesn't exist
    printf("\n[4.1] DELETE non-existent flow (observing behavior)\n");
    bool del_result = pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 60000, "12.11.10.9", 9999);
    printf("  [INFO] DELETE non-existent flow %s\n", del_result ? "succeeded (unexpected)" : "failed (expected)");
    // Don't count as pass/fail, just observe
    usleep(100000);

    return all_passed;
}

// Test Case 5: LOOKUP non-existent flow
bool test_case_5_lookup_nonexistent(int sockfd, int ifindex,
                                    FlowTable& local_table, TestStats& stats) {
    print_test_header("LOOKUP Non-existent Flow", 5);
    bool all_passed = true;

    // 5.1: LOOKUP flow that was never inserted
    printf("\n[5.1] LOOKUP non-existent flow (should not be found)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 7777, "192.168.1.1", 55555)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    return all_passed;
}

// Test Case 6: Different source ports
bool test_case_6_different_src_ports(int sockfd, int ifindex,
                                     FlowTable& local_table, TestStats& stats) {
    print_test_header("Different Source Ports", 6);
    bool all_passed = true;

    const int num_flows = 100;
    const uint16_t base_port = 50001;

    printf("\n[6] Testing %d flows with different source ports\n", num_flows);

    // INSERT flows with different source ports
    printf("\n  Phase 1: Inserting %d flows...\n", num_flows);
    for (int i = 0; i < num_flows; i++) {
        uint16_t port = base_port + i;
        if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", port, "12.11.10.9", 80)) {
            stats.passed++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(1000); // 1ms delay

        // Progress indicator every 20 flows
        if ((i + 1) % 20 == 0) {
            printf("    Progress: %d/%d flows inserted\n", i + 1, num_flows);
        }
    }

    // LOOKUP all flows
    printf("\n  Phase 2: Looking up %d flows...\n", num_flows);
    for (int i = 0; i < num_flows; i++) {
        uint16_t port = base_port + i;
        if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", port)) {
            stats.passed++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(1000); // 1ms delay

        // Progress indicator every 20 flows
        if ((i + 1) % 20 == 0) {
            printf("    Progress: %d/%d flows looked up\n", i + 1, num_flows);
        }
    }

    // Cleanup
    printf("\n  Phase 3: Cleaning up %d flows...\n", num_flows);
    for (int i = 0; i < num_flows; i++) {
        uint16_t port = base_port + i;
        pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", port, "12.11.10.9", 80);
        usleep(1000); // 1ms delay
    }

    return all_passed;
}

// Test Case 7: Different destination ports
bool test_case_7_different_dst_ports(int sockfd, int ifindex,
                                     FlowTable& local_table, TestStats& stats) {
    print_test_header("Different Destination Ports", 7);
    bool all_passed = true;

    uint16_t dst_ports[] = {80, 443, 8080, 8443, 3000};
    int num_flows = sizeof(dst_ports) / sizeof(dst_ports[0]);

    // INSERT flows to different destination ports
    for (int i = 0; i < num_flows; i++) {
        printf("\n[7.%d] INSERT flow 192.168.1.1:50100 -> 12.11.10.9:%d\n", i + 1, dst_ports[i]);
        if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 50100, "12.11.10.9", dst_ports[i])) {
            stats.passed++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(100000);
    }

    // LOOKUP all flows
    for (int i = 0; i < num_flows; i++) {
        printf("\n[7.%d] LOOKUP flow to port %d\n", num_flows + i + 1, dst_ports[i]);
        if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", dst_ports[i], "192.168.1.1", 50100)) {
            stats.passed++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(100000);
    }

    // Cleanup
    printf("\n[Cleanup] Deleting all flows\n");
    for (int i = 0; i < num_flows; i++) {
        pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 50100, "12.11.10.9", dst_ports[i]);
        usleep(100000);
    }

    return all_passed;
}

// Test Case 8: Interleaved INSERT and DELETE
bool test_case_8_interleaved_ops(int sockfd, int ifindex,
                                 FlowTable& local_table, TestStats& stats) {
    print_test_header("Interleaved INSERT and DELETE", 8);
    bool all_passed = true;

    // 8.1: INSERT flow 1
    printf("\n[8.1] INSERT flow 1: 192.168.1.1:51001 -> 12.11.10.9:80\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 51001, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 8.2: INSERT flow 2
    printf("\n[8.2] INSERT flow 2: 192.168.1.1:51002 -> 12.11.10.9:80\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 51002, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 8.3: DELETE flow 1
    printf("\n[8.3] DELETE flow 1\n");
    if (pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 51001, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 8.4: INSERT flow 3
    printf("\n[8.4] INSERT flow 3: 192.168.1.1:51003 -> 12.11.10.9:80\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 51003, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 8.5: LOOKUP flow 1 (should not exist)
    printf("\n[8.5] LOOKUP flow 1 (should not exist)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", 51001)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 8.6: LOOKUP flow 2 (should exist)
    printf("\n[8.6] LOOKUP flow 2 (should exist)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", 51002)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 8.7: LOOKUP flow 3 (should exist)
    printf("\n[8.7] LOOKUP flow 3 (should exist)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", 51003)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // Cleanup
    printf("\n[Cleanup] Deleting remaining flows\n");
    pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 51002, "12.11.10.9", 80);
    usleep(100000);
    pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 51003, "12.11.10.9", 80);
    usleep(100000);

    return all_passed;
}

// Test Case 9: Partial cleanup
bool test_case_9_partial_cleanup(int sockfd, int ifindex,
                                 FlowTable& local_table, TestStats& stats) {
    print_test_header("Partial Cleanup", 9);
    bool all_passed = true;

    // INSERT 4 flows
    uint16_t ports[] = {52001, 52002, 52003, 52004};
    for (int i = 0; i < 4; i++) {
        printf("\n[9.%d] INSERT flow %d: 192.168.1.1:%d -> 12.11.10.9:80\n", i + 1, i + 1, ports[i]);
        if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", ports[i], "12.11.10.9", 80)) {
            stats.passed++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(100000);
    }

    // DELETE flows 2 and 4
    printf("\n[9.5] DELETE flow 2\n");
    if (pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", ports[1], "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    printf("\n[9.6] DELETE flow 4\n");
    if (pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", ports[3], "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // LOOKUP all flows: 1 and 3 should exist, 2 and 4 should not
    printf("\n[9.7] LOOKUP flow 1 (should exist)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", ports[0])) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    printf("\n[9.8] LOOKUP flow 2 (should not exist)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", ports[1])) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    printf("\n[9.9] LOOKUP flow 3 (should exist)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", ports[2])) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    printf("\n[9.10] LOOKUP flow 4 (should not exist)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", ports[3])) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // Cleanup remaining flows
    printf("\n[Cleanup] Deleting remaining flows\n");
    pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", ports[0], "12.11.10.9", 80);
    usleep(100000);
    pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", ports[2], "12.11.10.9", 80);
    usleep(100000);

    return all_passed;
}

// Test Case 10: Stress test - many flows
bool test_case_10_stress_test(int sockfd, int ifindex,
                              FlowTable& local_table, TestStats& stats) {
    print_test_header("Stress Test - Many Flows", 10);
    bool all_passed = true;

    const int num_flows = 1000;
    printf("\n[10] INSERT, LOOKUP, and DELETE %d flows\n", num_flows);

    // INSERT many flows
    printf("\n  Phase 1: Inserting %d flows...\n", num_flows);
    int insert_success = 0;
    for (int i = 0; i < num_flows; i++) {
        uint16_t port = 53000 + i;
        if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", port, "12.11.10.9", 80)) {
            stats.passed++;
            insert_success++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(1000); // 1ms delay for stress test

        // Progress indicator every 100 flows
        if ((i + 1) % 100 == 0) {
            printf("    Progress: %d/%d flows inserted\n", i + 1, num_flows);
        }
    }
    printf("  Inserted %d/%d flows successfully\n", insert_success, num_flows);

    // LOOKUP all flows
    printf("\n  Phase 2: Looking up %d flows...\n", num_flows);
    int lookup_success = 0;
    for (int i = 0; i < num_flows; i++) {
        uint16_t port = 53000 + i;
        if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", port)) {
            stats.passed++;
            lookup_success++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(1000); // 1ms delay

        // Progress indicator every 100 flows
        if ((i + 1) % 100 == 0) {
            printf("    Progress: %d/%d flows looked up\n", i + 1, num_flows);
        }
    }
    printf("  Found %d/%d flows successfully\n", lookup_success, num_flows);

    // DELETE all flows
    printf("\n  Phase 3: Deleting %d flows...\n", num_flows);
    int delete_success = 0;
    for (int i = 0; i < num_flows; i++) {
        uint16_t port = 53000 + i;
        if (pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", port, "12.11.10.9", 80)) {
            stats.passed++;
            delete_success++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(1000); // 1ms delay

        // Progress indicator every 100 flows
        if ((i + 1) % 100 == 0) {
            printf("    Progress: %d/%d flows deleted\n", i + 1, num_flows);
        }
    }
    printf("  Deleted %d/%d flows successfully\n", delete_success, num_flows);

    printf("\n  [INFO] Stress test completed: %d flows processed\n", num_flows);

    return all_passed;
}

// Test Case 11: Sequential port numbers
bool test_case_11_sequential_ports(int sockfd, int ifindex,
                                   FlowTable& local_table, TestStats& stats) {
    print_test_header("Sequential Port Numbers", 11);
    bool all_passed = true;

    const uint16_t start_port = 54000;
    const int num_flows = 200;

    printf("\n[11] Testing %d flows with sequential ports %d-%d\n",
           num_flows, start_port, start_port + num_flows - 1);

    // INSERT flows with sequential ports
    printf("\n  Phase 1: Inserting %d flows with sequential ports...\n", num_flows);
    for (int i = 0; i < num_flows; i++) {
        uint16_t port = start_port + i;
        if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", port, "12.11.10.9", 80)) {
            stats.passed++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(1000); // 1ms delay

        // Progress indicator every 50 flows
        if ((i + 1) % 50 == 0) {
            printf("    Progress: %d/%d flows inserted\n", i + 1, num_flows);
        }
    }

    // LOOKUP in reverse order
    printf("\n  Phase 2: Looking up %d flows in reverse order...\n", num_flows);
    for (int i = num_flows - 1; i >= 0; i--) {
        uint16_t port = start_port + i;
        if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", port)) {
            stats.passed++;
        } else {
            stats.failed++;
            all_passed = false;
        }
        stats.total++;
        usleep(1000); // 1ms delay

        // Progress indicator every 50 flows
        if ((num_flows - i) % 50 == 0) {
            printf("    Progress: %d/%d flows looked up\n", num_flows - i, num_flows);
        }
    }

    // Cleanup
    printf("\n  Phase 3: Cleaning up %d flows...\n", num_flows);
    for (int i = 0; i < num_flows; i++) {
        uint16_t port = start_port + i;
        pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", port, "12.11.10.9", 80);
        usleep(1000); // 1ms delay
    }

    return all_passed;
}

// Test Case 12: Re-INSERT after DELETE
bool test_case_12_reinsert_after_delete(int sockfd, int ifindex,
                                        FlowTable& local_table, TestStats& stats) {
    print_test_header("Re-INSERT After DELETE", 12);
    bool all_passed = true;

    // 12.1: First INSERT
    printf("\n[12.1] INSERT flow 192.168.1.1:55000 -> 12.11.10.9:80\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 55000, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 12.2: DELETE
    printf("\n[12.2] DELETE flow\n");
    if (pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 55000, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 12.3: Re-INSERT same flow
    printf("\n[12.3] Re-INSERT same flow\n");
    if (pingpong_insert(sockfd, ifindex, local_table, "192.168.1.1", 55000, "12.11.10.9", 80)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // 12.4: LOOKUP (should find)
    printf("\n[12.4] LOOKUP re-inserted flow (should be found)\n");
    if (pingpong_lookup(sockfd, ifindex, local_table, "12.11.10.9", 80, "192.168.1.1", 55000)) {
        stats.passed++;
    } else {
        stats.failed++;
        all_passed = false;
    }
    stats.total++;
    usleep(100000);

    // Cleanup
    printf("\n[Cleanup] Deleting flow\n");
    pingpong_delete(sockfd, ifindex, local_table, "192.168.1.1", 55000, "12.11.10.9", 80);
    usleep(100000);

    return all_passed;
}
