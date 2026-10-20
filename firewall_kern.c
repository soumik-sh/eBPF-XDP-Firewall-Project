/*
 ============================================================================
 Project Name : eBPF + XDP High-Performance Firewall (Kernel Space)
 Author       : Soumik Debnath
 Description  : Implements a 4-tier security pipeline at the XDP driver layer:
                - Level 1: Packet ingestion, memory bounds checks, & Layer 2/3 parsing.
                - Level 2: Static IP filtering via manual blocklist map.
                - Level 3: Per-IP sliding-window rate limiting & DDoS mitigation.
                - Level 4: Stateful 4-tuple TCP connection tracking with 
                           bidirectional garbage collection on session teardown.
 ============================================================================
*/

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>

/* 
 * --- LEVEL 2: Manual Blocklist Map ---
 * Hash map storing manually blocked source IPv4 addresses.
 * Key   : u32 (IPv4 address in network byte order)
 * Value : u32 (Block flag = 1)
 * Max   : 256 entries
 */
BPF_HASH(blocklist, u32, u32, 256);

/* 
 * --- LEVEL 3: Rate Limiting Map & Configuration ---
 * Struct holding state for per-IP rate tracking over a sliding time window.
 */
struct rate_limit_val {
    u64 last_time;    // Monotonic kernel timestamp (nanoseconds) when the window started
    u32 packet_count; // Number of packets received from this IP within the current window
};

// BPF Hash Map for tracking traffic velocities per source IP
BPF_HASH(ratelimit_map, u32, struct rate_limit_val, 1024);

#define MAX_PACKETS_PER_SEC 100
#define TIME_WINDOW_NS      1000000000ULL // 1 second expressed in nanoseconds

/* 
 * --- LEVEL 4: Stateful Connection Tracking Map & Struct ---
 * Represents a TCP 4-tuple unique session identifier (Client/Server IP & Ports).
 */
struct conn_key {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

// BPF Hash Map tracking active established TCP sessions
BPF_HASH(conn_track, struct conn_key, u8, 1024);

/*
 * Main XDP Firewall Hook Function
 * Executed by the kernel network driver for every incoming packet.
 */
int xdp_firewall_prog(struct xdp_md *ctx) {
    // Pointer to the raw start of packet memory buffer
    void *data = (void *)(long)ctx->data;
    // Pointer to the exact end of packet memory buffer (strict verification boundary)
    void *data_end = (void *)(long)ctx->data_end;

    // --- LEVEL 1 (Part A): PARSE ETHERNET HEADER (Layer 2) ---
    struct ethhdr *eth = data;
    // Safety check: Ensure the Ethernet header does not exceed the packet buffer boundary
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Filter out non-IPv4 traffic (e.g., ARP, IPv6) and allow them to pass through
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- LEVEL 1 (Part B): PARSE IP HEADER (Layer 3) ---
    struct iphdr *ip = (void *)(eth + 1);
    // Safety check: Ensure the IP header does not exceed the packet buffer boundary
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 s_ip = ip->saddr; // Source IPv4 address
    u32 d_ip = ip->daddr; // Destination IPv4 address

    // ========================================================================
    // --- LEVEL 2: MANUAL BLOCKLIST CHECK ---
    // ========================================================================
    // Perform an O(1) hash map lookup to verify if the source IP is manually blocked
    if (blocklist.lookup(&s_ip)) {
        bpf_trace_printk("XDP Firewall: Blocked by manual blocklist.\n");
        return XDP_DROP; // Instantly drop packet at driver level
    }

    // ========================================================================
    // --- LEVEL 3: RATE LIMITING & DDOS MITIGATION ---
    // ========================================================================
    u64 current_time = bpf_ktime_get_ns(); // Fetch high-precision monotonic kernel time in ns
    struct rate_limit_val *rate_entry = ratelimit_map.lookup(&s_ip);

    if (rate_entry) {
        // Check if the 1-second sliding time window has elapsed
        if (current_time - rate_entry->last_time > TIME_WINDOW_NS) {
            rate_entry->last_time = current_time; // Reset window start timestamp
            rate_entry->packet_count = 1;         // Reset packet counter for the new window
        } else {
            // Atomically increment packet counter to prevent multi-core CPU race conditions
            __sync_fetch_and_add(&rate_entry->packet_count, 1);
            
            // If traffic velocity exceeds the threshold (>100 pkts/sec), drop subsequent packets
            if (rate_entry->packet_count > MAX_PACKETS_PER_SEC) {
                bpf_trace_printk("XDP Firewall: Rate limit exceeded! Dropping packet.\n");
                return XDP_DROP;
            }
        }
    } else {
        // First packet observed from this source IP: initialize rate-limit tracking struct
        struct rate_limit_val new_entry = {
            .last_time = current_time,
            .packet_count = 1
        };
        ratelimit_map.update(&s_ip, &new_entry);
    }

    // ========================================================================
    // --- LEVEL 4: STATEFUL CONNECTION TRACKING ---
    // ========================================================================
    // Inspect transport layer protocols, specifically focusing on TCP connection states
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        // Safety check: Ensure TCP header fits within the packet buffer
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        // Construct 4-tuple key representing the current packet connection path
        struct conn_key current_key = {
            .src_ip = s_ip,
            .dst_ip = d_ip,
            .src_port = tcp->source,
            .dst_port = tcp->dest
        };

        // Lookup whether this 4-tuple belongs to an existing established session
        u8 *state = conn_track.lookup(&current_key);
        if (state) {
            // Garbage Collection: Automatically clean up session mapping on TCP teardown flags (FIN or RST)
            if (tcp->fin || tcp->rst) {
                // 1. Delete the current matching key
                conn_track.delete(&current_key);
                
                // 2. Simultaneously delete the inverse/reverse key to keep bidirectional state fully synchronized
                struct conn_key reverse_key = {
                    .src_ip = d_ip,
                    .dst_ip = s_ip,
                    .src_port = tcp->dest,
                    .dst_port = tcp->source
                };
                conn_track.delete(&reverse_key);
            }
            return XDP_PASS; // Allow traffic belonging to established active sessions
        }

        // Monitor Outbound Connections: Detect locally initiated sessions via TCP SYN handshake
        if (tcp->syn && !tcp->ack) {
            u8 active = 1;
            
            // 1. Record Forward Tuple (Client -> Server path)
            conn_track.update(&current_key, &active);

            // 2. Record Reverse Tuple (Server -> Client path) to permit incoming server replies
            struct conn_key reverse_key = {
                .src_ip = d_ip,
                .dst_ip = s_ip,
                .src_port = tcp->dest,
                .dst_port = tcp->source
            };
            conn_track.update(&reverse_key, &active);
            return XDP_PASS;
        }

        // Default Stateful Security Policy: Drop all unsolicited incoming TCP traffic
        bpf_trace_printk("XDP Firewall: Dropped unsolicited inbound TCP packet.\n");
        return XDP_DROP;
    }

    // Default policy: Allow all other permitted protocols (e.g., standard ICMP / DNS)
    return XDP_PASS;
}
