#include "flow_table.h"
#include <arpa/inet.h>
#include <sstream>
#include <iostream>

// Convert FiveTuple to string for display
std::string FiveTuple::to_string() const {
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = src_ip;
    dst_addr.s_addr = dst_ip;

    std::ostringstream oss;
    oss << inet_ntoa(src_addr) << ":" << src_port << " -> "
        << inet_ntoa(dst_addr) << ":" << dst_port
        << " (proto=" << (int)protocol << ")";
    return oss.str();
}

// Insert a flow into the table
bool FlowTable::insert(const FiveTuple& ft) {
    auto result = flows.insert(ft);
    return result.second; // true if inserted, false if already exists
}

// Delete a flow from the table
bool FlowTable::remove(const FiveTuple& ft) {
    return flows.erase(ft) > 0;
}

// Check if a flow exists in the table
bool FlowTable::exists(const FiveTuple& ft) const {
    return flows.find(ft) != flows.end();
}

// Get the number of flows in the table
size_t FlowTable::size() const {
    return flows.size();
}

// Clear all flows
void FlowTable::clear() {
    flows.clear();
}

// Print all flows
void FlowTable::print_all() const {
    std::cout << "=== Local Flow Table (" << flows.size() << " flows) ===" << std::endl;
    for (const auto& ft : flows) {
        std::cout << "  " << ft.to_string() << std::endl;
    }
}
