#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <stdint.h>
#include <string>
#include <unordered_set>

// 5-tuple structure for flow identification
struct FiveTuple {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t protocol;

    // Equality operator for unordered_set
    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               src_port == other.src_port &&
               dst_ip == other.dst_ip &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }

    // Convert to string for display
    std::string to_string() const;
};

// Hash function for FiveTuple
namespace std {
    template <>
    struct hash<FiveTuple> {
        size_t operator()(const FiveTuple& ft) const {
            size_t h1 = hash<uint32_t>()(ft.src_ip);
            size_t h2 = hash<uint16_t>()(ft.src_port);
            size_t h3 = hash<uint32_t>()(ft.dst_ip);
            size_t h4 = hash<uint16_t>()(ft.dst_port);
            size_t h5 = hash<uint8_t>()(ft.protocol);
            return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
        }
    };
}

// Local flow table for tracking inserted flows
class FlowTable {
private:
    std::unordered_set<FiveTuple> flows;

public:
    // Insert a flow into the table
    bool insert(const FiveTuple& ft);

    // Delete a flow from the table
    bool remove(const FiveTuple& ft);

    // Check if a flow exists in the table
    bool exists(const FiveTuple& ft) const;

    // Get the number of flows in the table
    size_t size() const;

    // Clear all flows
    void clear();

    // Print all flows
    void print_all() const;
};

#endif // FLOW_TABLE_H
