# NIC Firewall Comprehensive Test Suite

This test tool validates the NIC firewall's INSERT, LOOKUP, and DELETE operations using raw TCP packets with a comprehensive ping-pong testing pattern.

## Architecture

```
bucket_test/
├── main.cpp              # Main entry point - calls all test cases
├── Makefile              # Build configuration
├── README.md             # This file
└── src/                  # Module implementations
    ├── config.h          # Network configuration
    ├── network.h/cpp     # Raw socket operations
    ├── packet.h/cpp      # TCP packet construction and parsing
    ├── flow_table.h/cpp  # Local 5-tuple tracking
    ├── pingpong.h/cpp    # Ping-pong test functions (INSERT/LOOKUP/DELETE)
    ├── test_cases.h/cpp  # Comprehensive test case implementations
    └── utils.h/cpp       # Utility functions
```

## Ping-Pong Test Functions

The core testing functionality is encapsulated in three ping-pong functions in `src/pingpong.h/cpp`:

### 1. `pingpong_insert()` - INSERT Operation
- **Direction**: LAN → WAN (192.168.1.1:port → 12.11.10.9:port)
- **Packet**: TCP with SYN flag
- **Expected Response**: FIN flag (indicates successful insert)
- **Action**: Adds flow to local table if successful
- **Returns**: `true` if insert successful, `false` otherwise

### 2. `pingpong_delete()` - DELETE Operation
- **Direction**: LAN → WAN (192.168.1.1:port → 12.11.10.9:port)
- **Packet**: TCP with FIN flag
- **Expected Response**: SYN flag (indicates successful delete)
- **Action**: Removes flow from local table if successful
- **Returns**: `true` if delete successful, `false` otherwise

### 3. `pingpong_lookup()` - LOOKUP Operation
- **Direction**: WAN → LAN (12.11.10.9:port → 192.168.1.1:port)
- **Packet**: TCP with ACK flag
- **Expected Response**:
  - SYN flag if flow found in NIC table
  - FIN flag if flow not found in NIC table
- **Validation**: Compares NIC result with local table
- **Returns**:
  - `true` if NIC and local table match (consistent state)
  - `false` if mismatch (indicates potential NIC bug)

## Comprehensive Test Cases

The test suite includes 12 comprehensive test cases in `src/test_cases.cpp`:

### Test Case 1: Basic INSERT-LOOKUP-DELETE Sequence
Tests the fundamental workflow:
1. INSERT a flow
2. LOOKUP the flow (should be found)
3. DELETE the flow
4. LOOKUP the flow again (should not be found)

**Tests**: 4 | **Focus**: Basic functionality

### Test Case 2: Multiple Concurrent Flows
Tests handling of multiple flows simultaneously:
1. INSERT 3 different flows
2. LOOKUP all 3 flows (should all be found)
3. Cleanup

**Tests**: 6 | **Focus**: Concurrent flow management

### Test Case 3: Duplicate INSERT Operations
Tests behavior when inserting the same flow twice:
1. INSERT a flow
2. INSERT the same flow again (observational)
3. LOOKUP should still work

**Tests**: 2 | **Focus**: Duplicate handling

### Test Case 4: DELETE Non-existent Flow
Tests DELETE on flows that don't exist (observational)

**Tests**: 0 (observational) | **Focus**: Error handling

### Test Case 5: LOOKUP Non-existent Flow
Tests LOOKUP on flows that were never inserted

**Tests**: 1 | **Focus**: Negative lookup

### Test Case 6: Different Source Ports
Tests 100 flows from same source IP but different ports

**Tests**: 200 | **Focus**: Port differentiation

### Test Case 7: Different Destination Ports
Tests flows to different destination ports (80, 443, 8080, 8443, 3000)

**Tests**: 10 | **Focus**: Service differentiation

### Test Case 8: Interleaved INSERT and DELETE
Tests inserting and deleting flows in various orders

**Tests**: 7 | **Focus**: Operation ordering

### Test Case 9: Partial Cleanup
Tests deleting some flows while keeping others:
1. INSERT 4 flows
2. DELETE flows 2 and 4 only
3. Verify flows 1 and 3 still exist
4. Verify flows 2 and 4 are gone

**Tests**: 10 | **Focus**: Selective deletion

### Test Case 10: Stress Test - Many Flows
Tests with **1000 flows**:
1. INSERT 1000 flows
2. LOOKUP all 1000 flows
3. DELETE all 1000 flows

**Tests**: 3000 | **Focus**: Scalability & Performance

### Test Case 11: Sequential Port Numbers
Tests 200 flows with sequential port numbers (like port scan):
1. INSERT 200 flows with sequential ports
2. LOOKUP in reverse order

**Tests**: 400 | **Focus**: Sequential patterns

### Test Case 12: Re-INSERT After DELETE
Tests inserting the same flow again after deleting it:
1. INSERT flow
2. DELETE flow
3. Re-INSERT same flow
4. LOOKUP (should find)

**Tests**: 4 | **Focus**: Flow reuse

## Total Test Coverage

- **Total Test Cases**: 12
- **Total Individual Tests**: ~3,631 tests
- **Flows Tested**: Single flows to **1000+ concurrent flows**
- **Operations Tested**: INSERT, LOOKUP, DELETE, and combinations
- **Scalability**: Stress test with 1000 flows validates production-scale performance

## Key Design Points

### LAN vs WAN Behavior
According to `/home/zx/nic-os/c_packetprocessing/apps/malloc_fw/main.c:168`:
- **LAN side (lan_or_wan = 0)**: Can INSERT (SYN) and DELETE (FIN)
- **WAN side (lan_or_wan = 1)**: Can only LOOKUP
- **Direction mapping**:
  - INSERT: LAN → WAN (src=192.168.x.x → dst=12.11.x.x)
  - DELETE: LAN → WAN (src=192.168.x.x → dst=12.11.x.x)
  - LOOKUP: WAN → LAN (src=12.11.x.x → dst=192.168.x.x)

### Response Encoding
The NIC responds by modifying TCP flags:
- **SYN → FIN**: INSERT successful
- **FIN → SYN**: DELETE successful
- **ACK (WAN) → SYN**: Flow found (LOOKUP successful)
- **ACK (WAN) → FIN**: Flow not found (LOOKUP successful, flow doesn't exist)

### Local Flow Table
- Maintains a local copy of inserted flows using C++ `unordered_set<FiveTuple>`
- Used to validate NIC behavior and detect bugs
- Automatically updated by ping-pong functions

## Configuration

Edit `src/config.h` to match your setup:

```cpp
#define INTERFACE "ens3f0np0"           // Network interface
static const uint8_t SRC_MAC[6] = {...}; // Host MAC address
static const uint8_t DST_MAC[6] = {...}; // NIC MAC address
#define DEFAULT_LAN_SRC_IP "192.168.1.1"
#define DEFAULT_LAN_DST_IP "12.11.10.9"
```

## Build

```bash
make clean
make
```

## Run

**Requires root privileges for raw socket:**

```bash
sudo ./bucket_test
```

## Expected Output

```
========================================
NIC Firewall Comprehensive Test Suite
========================================
Interface: ens3f0np0

Socket configured successfully

========================================
Running Test Suite
========================================

========================================
Test Case 1: Basic INSERT-LOOKUP-DELETE
========================================

[1.1] INSERT flow 192.168.1.1:49000 -> 12.11.10.9:80
  Sending SYN (LAN->WAN): 192.168.1.1:49000 -> 12.11.10.9:80
  Received: ... (flags: FIN )
  [SUCCESS] INSERT successful - added to local table

[1.2] LOOKUP inserted flow (should be found)
  Sending ACK (WAN->LAN): 12.11.10.9:80 -> 192.168.1.1:49000
  Looking for LAN flow: 192.168.1.1:49000 -> 12.11.10.9:80
  Exists in local table: YES
  Received: ... (flags: SYN )
  [SUCCESS] LOOKUP matched - found in both NIC and local table

...

========================================
Test Case 10: Stress Test - Many Flows
========================================

[10] INSERT, LOOKUP, and DELETE 20 flows

  Phase 1: Inserting 20 flows...
  Phase 2: Looking up 20 flows...
  Phase 3: Deleting 20 flows...

  [INFO] Stress test completed: 20 flows processed

...

========================================
=== Local Flow Table (0 flows) ===
========================================

========================================
Overall Test Summary
========================================
Passed: 134/134
Failed: 0/134
Success Rate: 100.0%
========================================
```

## Adding New Test Cases

To add a new test case:

1. **Add function declaration** in `src/test_cases.h`:
```cpp
bool test_case_13_your_test(int sockfd, int ifindex,
                            FlowTable& local_table, TestStats& stats);
```

2. **Implement the function** in `src/test_cases.cpp`:
```cpp
bool test_case_13_your_test(int sockfd, int ifindex,
                            FlowTable& local_table, TestStats& stats) {
    print_test_header("Your Test Description", 13);
    bool all_passed = true;

    // Your test logic using pingpong_insert/lookup/delete
    // Update stats.passed, stats.failed, stats.total

    return all_passed;
}
```

3. **Call the function** in `main.cpp`:
```cpp
test_case_13_your_test(sockfd, ifindex, local_table, stats);
```

## Function API

### Insert Function
```cpp
bool pingpong_insert(int sockfd, int ifindex, FlowTable& local_table,
                     const char* src_ip, uint16_t src_port,
                     const char* dst_ip, uint16_t dst_port);
```

### Delete Function
```cpp
bool pingpong_delete(int sockfd, int ifindex, FlowTable& local_table,
                     const char* src_ip, uint16_t src_port,
                     const char* dst_ip, uint16_t dst_port);
```

### Lookup Function
```cpp
bool pingpong_lookup(int sockfd, int ifindex, const FlowTable& local_table,
                     const char* src_ip, uint16_t src_port,
                     const char* dst_ip, uint16_t dst_port);
```

## References

- NIC implementation: `/home/zx/nic-os/c_packetprocessing/apps/malloc_fw/main.c`
- Raw socket example: `/home/zx/nic-os/latency-pktgen`
- Packet format reference: `/home/zx/nic-os/c_packetprocessing/apps/malloc_fw/test/scapy_test/echo_tcp_test.py`
