#ifndef TEST_CASES_H
#define TEST_CASES_H

#include "flow_table.h"

// Test statistics structure
struct TestStats {
    int passed;
    int failed;
    int total;
};

// Test case functions
// Each function returns true if all tests in that case pass, false otherwise

/**
 * Test Case 1: Basic INSERT-LOOKUP-DELETE sequence
 * Tests the fundamental workflow of inserting, looking up, and deleting a single flow
 */
bool test_case_1_basic_insert_lookup_delete(int sockfd, int ifindex,
                                             FlowTable& local_table, TestStats& stats);

/**
 * Test Case 2: Multiple concurrent flows
 * Tests handling of multiple flows simultaneously
 */
bool test_case_2_multiple_flows(int sockfd, int ifindex,
                                FlowTable& local_table, TestStats& stats);

/**
 * Test Case 3: Duplicate INSERT operations
 * Tests behavior when trying to insert the same flow twice
 */
bool test_case_3_duplicate_insert(int sockfd, int ifindex,
                                  FlowTable& local_table, TestStats& stats);

/**
 * Test Case 4: DELETE non-existent flow
 * Tests behavior when trying to delete a flow that doesn't exist
 */
bool test_case_4_delete_nonexistent(int sockfd, int ifindex,
                                    FlowTable& local_table, TestStats& stats);

/**
 * Test Case 5: LOOKUP non-existent flow
 * Tests behavior when looking up flows that were never inserted
 */
bool test_case_5_lookup_nonexistent(int sockfd, int ifindex,
                                    FlowTable& local_table, TestStats& stats);

/**
 * Test Case 6: Different source ports
 * Tests multiple flows from same source IP but different ports
 */
bool test_case_6_different_src_ports(int sockfd, int ifindex,
                                     FlowTable& local_table, TestStats& stats);

/**
 * Test Case 7: Different destination ports
 * Tests flows to different destination ports
 */
bool test_case_7_different_dst_ports(int sockfd, int ifindex,
                                     FlowTable& local_table, TestStats& stats);

/**
 * Test Case 8: Interleaved INSERT and DELETE
 * Tests inserting and deleting flows in various orders
 */
bool test_case_8_interleaved_ops(int sockfd, int ifindex,
                                 FlowTable& local_table, TestStats& stats);

/**
 * Test Case 9: Partial cleanup
 * Tests deleting some flows while keeping others
 */
bool test_case_9_partial_cleanup(int sockfd, int ifindex,
                                 FlowTable& local_table, TestStats& stats);

/**
 * Test Case 10: Stress test - many flows
 * Tests with a larger number of flows
 */
bool test_case_10_stress_test(int sockfd, int ifindex,
                              FlowTable& local_table, TestStats& stats);

/**
 * Test Case 11: Sequential port numbers
 * Tests flows with sequential port numbers (like port scan)
 */
bool test_case_11_sequential_ports(int sockfd, int ifindex,
                                   FlowTable& local_table, TestStats& stats);

/**
 * Test Case 12: Re-INSERT after DELETE
 * Tests inserting the same flow again after deleting it
 */
bool test_case_12_reinsert_after_delete(int sockfd, int ifindex,
                                        FlowTable& local_table, TestStats& stats);

// Helper function to print test case header
void print_test_header(const char* test_name, int test_number);

// Helper function to print test statistics
void print_test_stats(const TestStats& stats);

#endif // TEST_CASES_H
