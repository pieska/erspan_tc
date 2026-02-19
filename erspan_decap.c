#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define PULLED_DATA_SIZE 128
#define ERSPAN_SESSION_MASK 0x03FF
#define GRE_PROTOCOL_ERSPAN 0x88be

/* GRE Flags according to RFC 2784 / 2890 */
#define GRE_FLAG_CKSUM 0x8000
#define GRE_FLAG_KEY   0x2000
#define GRE_FLAG_SEQ   0x1000

/* Define a clean debug macro (without newlines as requested) */
#ifdef DEBUG
#define bpf_debug(fmt, ...) bpf_printk("erspan_decap: " fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...)
#endif

/* header structure
outer IPv4 Header: 20 Bytes (IHL=5)
GRE Header (Base): 4 Bytes
GRE Checksum: +4 Bytes (if checksum present set)
GRE Key: +4 Bytes (if key present set)
GRE Sequence: +4 Bytes (if sequence# present set)
ERSPAN Header: 8 Bytes
*/

/* ERSPAN type II header struct (8 bytes) */
struct erspanhdr {
    __be16 ver_vlan;           
    __be16 session_id;         
    __be32 flags_index;        
} __attribute__((packed));

/* GRE header struct (min 4 bytes) */
struct grehdr {
    __be16 flags;              
    __be16 protocol;           
} __attribute__((packed));

/* Custom struct to hold all configuration data */
struct config_data {
    __u32 target_ifindex;
    __u16 session_id;
};

/* Struct for our per-CPU statistics */
struct stats_record {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 drop_session_filtered;
    __u64 drop_errors;
};

/* Single consolidated configuration map (max 15 chars: erspan_cfg_map) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);    
    __type(key, __u32);
    __type(value, struct config_data);      
} erspan_cfg_map SEC(".maps");

/* Per-CPU Array Map for statistics (max 15 chars: erspan_stat_map) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_record);
} erspan_stat_map SEC(".maps");

SEC("classifier")
int tc_erspan_decap(struct __sk_buff *skb) {
    bpf_debug("--- New packet received ---");

    __u32 key = 0;
    
    /* Lookup config and stats pointers at the start using the new map names */
    struct config_data *cfg = bpf_map_lookup_elem(&erspan_cfg_map, &key);
    struct stats_record *stats = bpf_map_lookup_elem(&erspan_stat_map, &key);

    /* Force kernel to pull enough data linear in memory to prevent verifier issues */
    if (bpf_skb_pull_data(skb, PULLED_DATA_SIZE) < 0) {
        bpf_debug("Error: bpf_skb_pull_data failed");
        if (stats) stats->drop_errors++;
        return TC_ACT_OK;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse outer L2 (Ethernet) header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_debug("Drop: Packet too small for Ethernet header");
        if (stats) stats->drop_errors++;
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bpf_debug("Skip: Not an IPv4 packet (eth_proto=0x%x)", bpf_ntohs(eth->h_proto));
        return TC_ACT_OK;
    }

    /* Parse outer L3 (IPv4) header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_debug("Drop: Packet too small for IPv4 header");
        if (stats) stats->drop_errors++;
        return TC_ACT_OK;
    }

    /* Ensure protocol is GRE and skip IP options if present */
    if (iph->protocol != IPPROTO_GRE || iph->ihl < 5) {
        bpf_debug("Skip: Not a valid GRE packet (proto=%d, ihl=%d)", iph->protocol, iph->ihl);
        return TC_ACT_OK;
    }

    /* Parse GRE header */
    struct grehdr *gre = (void *)iph + (iph->ihl * 4); 
    if ((void *)(gre + 1) > data_end) {
        bpf_debug("Drop: Packet too small for GRE header");
        if (stats) stats->drop_errors++;
        return TC_ACT_OK;
    }

    if (gre->protocol != bpf_htons(GRE_PROTOCOL_ERSPAN)) {
        bpf_debug("Skip: GRE protocol is not ERSPAN (gre_proto=0x%x)", bpf_ntohs(gre->protocol));
        return TC_ACT_OK;
    }

    __u16 gre_flags = bpf_ntohs(gre->flags);
    __u32 offset_add = 0;

    bpf_debug("GRE flags detected: 0x%x", gre_flags);

    /* Calculate offset to skip optional GRE fields (Checksum, Key, Sequence) */
    if (gre_flags & GRE_FLAG_CKSUM) offset_add += 4;
    if (gre_flags & GRE_FLAG_KEY)   offset_add += 4;
    if (gre_flags & GRE_FLAG_SEQ)   offset_add += 4;

    void *erspan_ptr = (void *)(gre + 1) + offset_add;

    /* Bounds check before accessing ERSPAN header */
    if (erspan_ptr + sizeof(struct erspanhdr) > data_end) {
        bpf_debug("Drop: Packet too small for ERSPAN header (offset=%u)", offset_add);
        if (stats) stats->drop_errors++;
        return TC_ACT_OK;
    }

    struct erspanhdr *erspan = erspan_ptr;

    /* Verify ERSPAN Type II (Version must be 1 according to RFC 8892) */
    __u16 ver_vlan = bpf_ntohs(erspan->ver_vlan);
    __u8 version = (ver_vlan >> 12) & 0xF;
    if (version != 1) {
        bpf_debug("Skip: Not ERSPAN Type II (version=%u)", version);
        return TC_ACT_OK;
    }

    /* Mask to extract the 10-bit session ID */
    __u16 session_id = bpf_ntohs(erspan->session_id) & ERSPAN_SESSION_MASK;
    bpf_debug("Found ERSPAN session ID: %u", session_id);

    /* Check Session ID against config */
    if (cfg && cfg->session_id != 0 && session_id != cfg->session_id) {
        bpf_debug("Skip: Session ID %u filtered (expected %u)", session_id, cfg->session_id);
        if (stats) stats->drop_session_filtered++;
        return TC_ACT_OK;
    }

    /* Calculate total length of encapsulation headers to be stripped */
    __u32 erspan_off = (__u32)((void *)erspan - data);
    __u32 total_strip_len = erspan_off + sizeof(struct erspanhdr);

    bpf_debug("Preparing to strip %u bytes of encapsulation headers", total_strip_len);

    /* Ensure strip length doesn't exceed pulled data and leaves room for inner MAC */
    if (total_strip_len > PULLED_DATA_SIZE || (total_strip_len + sizeof(struct ethhdr)) > PULLED_DATA_SIZE) {
        bpf_debug("Error: strip_len %u exceeds safe bounds", total_strip_len);
        if (stats) stats->drop_errors++;
        return TC_ACT_OK;
    }

    /* 1. Read and save the inner L2 (Ethernet) header from the payload */
    struct ethhdr inner_mac;
    if (bpf_skb_load_bytes(skb, total_strip_len, &inner_mac, sizeof(inner_mac)) < 0) {
        bpf_debug("Error: bpf_skb_load_bytes failed to read inner MAC");
        if (stats) stats->drop_errors++;
        return TC_ACT_SHOT;
    }

    /* 2. Copy the inner L2 header to the start of the packet, overwriting the outer L2 header */
    if (bpf_skb_store_bytes(skb, 0, &inner_mac, sizeof(inner_mac), 0) < 0) {
        bpf_debug("Error: bpf_skb_store_bytes failed to write inner MAC");
        if (stats) stats->drop_errors++;
        return TC_ACT_SHOT;
    }

    /* 3. Adjust packet room to remove the outer headers. */
    if (bpf_skb_adjust_room(skb, -(__s32)total_strip_len, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO)) {
        bpf_debug("Error: bpf_skb_adjust_room failed to remove %u bytes", total_strip_len);
        if (stats) stats->drop_errors++;
        return TC_ACT_SHOT; 
    }

    /* Update success stats */
    if (stats) {
        stats->rx_packets++;
        stats->rx_bytes += skb->len;
    }

    bpf_debug("Decapsulation successful. Checking redirect target...");

    if (!cfg || cfg->target_ifindex == 0) {
        bpf_debug("Warning: No target ifindex configured. Passing to normal stack.");
        return TC_ACT_OK; 
    }

    bpf_debug("Redirecting packet to ifindex %u (Ingress)", cfg->target_ifindex);

    /* 5. Redirect the fully decapsulated packet to the target interface ingress */
    return bpf_redirect(cfg->target_ifindex, BPF_F_INGRESS);
}

char _license[] SEC("license") = "GPL";

