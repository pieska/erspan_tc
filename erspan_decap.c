#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define PULLED_DATA_LIMIT 128
#define ERSPAN_SESSION_MASK 0x03FF
#define GRE_PROTOCOL_ERSPAN 0x88be

// map key for config and stats map
#define MAP_KEY 0

#define ETH_P_8021AD 0x88A8

#define GRE_FLAG_CKSUM 0x8000
#define GRE_FLAG_KEY   0x2000
#define GRE_FLAG_SEQ   0x1000

#ifdef DEBUG
#define bpf_debug(fmt, ...) bpf_printk("erspan_decap: " fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...)
#endif

/* likely/unlikely: branch prediction hints for hot/cold paths */
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* ERSPAN type II header struct (8 bytes) */
struct erspanhdr {
    __be16 ver_vlan;
    __be16 cos_en_t_sid;
    __be32 reserved_index;
} __attribute__((packed));

/* GRE header struct (min 4 bytes) */
struct grehdr {
    __be16 flags;
    __be16 protocol;
} __attribute__((packed));

/* 802.1Q VLAN tag (4 bytes) */
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

/* configuration data */
struct config_data {
    __u32 target_ifindex;
    __u16 session_id;
    __u16 __pad;            /* session_id + padding == 32 bits */
};

/* per-CPU stats */
struct stats_record {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 drop_session_filtered;
};

/* configuration map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config_data);
} erspan_cfg_map SEC(".maps");

/* stats map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_record);
} erspan_stat_map SEC(".maps");

SEC("classifier")
int tc_erspan_decap(struct __sk_buff *skb) {
    bpf_debug("--- New packet received ---");

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* parse outer L2 (Ethernet) header */
    struct ethhdr *eth = data;
    if (unlikely((void *)(eth + 1) > data_end)) {
        bpf_debug("Drop: Packet too small for Ethernet header");
        return TC_ACT_OK;
    }

    /* parse vlan header */
    __be16 eth_proto = eth->h_proto;
    __u32 l3_offset = sizeof(struct ethhdr);

    if (eth_proto == bpf_htons(ETH_P_8021Q) ||
        eth_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan = data + l3_offset;
        if (unlikely((void *)(vlan + 1) > data_end)) {
            bpf_debug("Drop: Packet too small for VLAN header");
            return TC_ACT_OK;
        }
        eth_proto = vlan->h_vlan_encapsulated_proto;
        l3_offset += sizeof(struct vlan_hdr);

        /* QinQ: 802.1ad outer + 802.1Q inner */
        if (eth_proto == bpf_htons(ETH_P_8021Q)) {
            vlan = data + l3_offset;
            if (unlikely((void *)(vlan + 1) > data_end)) {
                bpf_debug("Drop: Packet too small for inner VLAN header");
                return TC_ACT_OK;
            }
            eth_proto = vlan->h_vlan_encapsulated_proto;
            l3_offset += sizeof(struct vlan_hdr);
        }
    }

    if (unlikely(eth_proto != bpf_htons(ETH_P_IP))) {
        bpf_debug("Skip: Not an IPv4 packet (eth_proto=0x%x)", bpf_ntohs(eth_proto));
        return TC_ACT_OK;
    }

    /* parse outer L3 (IPv4) header */
    struct iphdr *iph = data + l3_offset;
    if (unlikely((void *)(iph + 1) > data_end)) {
        bpf_debug("Drop: Packet too small for IPv4 header");
        return TC_ACT_OK;
    }

    /* check protocol is GRE w/o options */
    if (unlikely(iph->protocol != IPPROTO_GRE || iph->ihl != 5)) {
        bpf_debug("Skip: Not a valid GRE packet (proto=%d, ihl=%d)", iph->protocol, iph->ihl);
        return TC_ACT_OK;
    }

    /* it's GRE: pull full frame into linear memory */
    __u32 pull_len = skb->len < PULLED_DATA_LIMIT ? skb->len : PULLED_DATA_LIMIT;
    if (unlikely(bpf_skb_pull_data(skb, pull_len) < 0)) {
        bpf_debug("Error: bpf_skb_pull_data failed");
        return TC_ACT_OK;
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    /* IP header */
    iph = data + l3_offset;
    if (unlikely((void *)(iph + 1) > data_end)) {
        bpf_debug("Drop: IPv4 header out of bounds after pull_data (l3_off=%u)", l3_offset);
        return TC_ACT_OK;
    }

    /* GRE header */
    struct grehdr *gre = (void *)(iph + 1);
    if (unlikely((void *)(gre + 1) > data_end)) {
        bpf_debug("Drop: GRE header out of bounds after pull_data");
        return TC_ACT_OK;
    }

    if (unlikely(gre->protocol != bpf_htons(GRE_PROTOCOL_ERSPAN))) {
        bpf_debug("Skip: GRE protocol is not ERSPAN (gre_proto=0x%x)", bpf_ntohs(gre->protocol));
        return TC_ACT_OK;
    }

    __u16 gre_flags = bpf_ntohs(gre->flags);

    if (unlikely(gre_flags & 0x0007)) {  /* GRE Version != 0 */
        bpf_debug("Skip: GRE is not standard GREv0");
        return TC_ACT_OK;
    }

    if (unlikely(!(gre_flags & GRE_FLAG_SEQ))) {
        bpf_debug("Skip: No seq bit set");
        return TC_ACT_OK;
    }

    __u32 offset_add = 0;
    if (gre_flags & GRE_FLAG_CKSUM) offset_add += 4;
    if (gre_flags & GRE_FLAG_KEY)   offset_add += 4;
    if (gre_flags & GRE_FLAG_SEQ)   offset_add += 4;

    void *erspan_ptr = (void *)(gre + 1) + offset_add;

    /* bounds check before accessing ERSPAN header */
    if (unlikely(erspan_ptr + sizeof(struct erspanhdr) > data_end)) {
        bpf_debug("Drop: Packet too small for ERSPAN header (offset=%u)", offset_add);
        return TC_ACT_OK;
    }

    struct erspanhdr *erspan = erspan_ptr;

    /* verify ERSPAN Type II (version must be 1, draft-foschiano-erspan-03) */
    __u16 ver_vlan = bpf_ntohs(erspan->ver_vlan);
    __u8 version = (ver_vlan >> 12) & 0xF;
    if (unlikely(version != 1)) {
        bpf_debug("Skip: Not ERSPAN Type II (version=%u)", version);
        return TC_ACT_OK;
    }

    /* extract the 10-bit session ID */
    __u16 session_id = bpf_ntohs(erspan->cos_en_t_sid) & ERSPAN_SESSION_MASK;
    bpf_debug("Found ERSPAN session ID: %u", session_id);

    /* load config and stats pointers */
    __u32 map_key = MAP_KEY;
    struct config_data *cfg = bpf_map_lookup_elem(&erspan_cfg_map, &map_key);
    struct stats_record *stats = bpf_map_lookup_elem(&erspan_stat_map, &map_key);

    /* check Session ID against config, 0 means any */
    if (unlikely(cfg && cfg->session_id != 0 && cfg->session_id != session_id)) {
        bpf_debug("Skip: Session ID %u filtered (expected %u)", session_id, cfg->session_id);
        if (stats) stats->drop_session_filtered++;
        return TC_ACT_OK;
    }

     /*
     * total_strip_len = outer_ETH [+ VLAN(s)] + outer_IP + GRE(+opts) + ERSPAN
     */
    __u32 erspan_off = (__u32)((void *)erspan - data);
    __u32 total_strip_len = erspan_off + sizeof(struct erspanhdr);

    bpf_debug("Preparing to strip %u bytes of encapsulation headers", total_strip_len);

    /* ensure strip length doesn't exceed pulled data and leaves room for inner MAC */
    if (unlikely(total_strip_len + sizeof(struct ethhdr) > PULLED_DATA_LIMIT)) {
        bpf_debug("Error: strip_len %u exceeds safe bounds", total_strip_len);
        return TC_ACT_OK;
    }

    /* decapsulate using BPF_ADJ_ROOM_MAC, requires kernel >= 5.2 */
    if (unlikely(bpf_skb_adjust_room(skb, -(__s32)total_strip_len, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO))) {
        bpf_debug("Error: bpf_skb_adjust_room failed to remove %u bytes", total_strip_len);
        return TC_ACT_SHOT;
    }

    /* update success stats */
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

    /* redirect the decapsulated packet to the target interface ingress */
    return bpf_redirect(cfg->target_ifindex, BPF_F_INGRESS);
}

char _license[] SEC("license") = "GPL";

