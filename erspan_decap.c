#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ERSPAN Type II Header struct (8 bytes)*/
struct erspanhdr {
    __be16 ver_vlan;           // 4-bit version (2) + 12-bit VLAN ID
    __be16 session_id;         // first 10-bit are session ID
    __be32 flags_index;        // flags and sequencenumber/index
} __attribute__((packed));     // prevent padding

/* GRE Header struct (min 4 Bytes) */
struct grehdr {
    __be16 flags;              // flags like key (0x2000) or sequence (0x1000)
    __be16 protocol;           // 0x88be für ERSPAN
} __attribute__((packed));

/* config-map to change session-ID at run-time */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);    // need only 1 entry
    __type(key, __u32);
    __type(value, __u16);      // to fit in 10bit session-ID
} config_map SEC(".maps");     // BPF-map

SEC("classifier")
int tc_erspan_decap(struct __sk_buff *skb) {
    // force kernel to allocate linear the first 128 bytes
    // otherwise verifier has issues with jumbo frames
    if (bpf_skb_pull_data(skb, 128) < 0) {
        return TC_ACT_OK;
    }

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // check ethernet header L2
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)		// verifier-check
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // check outer IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)		// verifier-check
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_GRE)
        return TC_ACT_OK;

    // analyze GRE header, iph->ihl * 4, if IP-header has options
    struct grehdr *gre = (void *)iph + (iph->ihl * 4); 
    if ((void *)(gre + 1) > data_end)		// verifier-check
        return TC_ACT_OK;

    if (gre->protocol != bpf_htons(0x88be))	// GRE-Protokoll ERSPAN (0x88be)
        return TC_ACT_OK;

    // skip over GRE options
    void *erspan_ptr = (void *)(gre + 1);
    __u16 gre_flags = bpf_ntohs(gre->flags);

    if (gre_flags & 0x2000) {			// GRE key
        erspan_ptr += 4;
    }
    if (gre_flags & 0x1000) {			// GRE seq
        erspan_ptr += 4;
    }

    // extract ERSPAN session-ID
    struct erspanhdr *erspan = erspan_ptr;
    if ((void *)(erspan + 1) > data_end)	// verified-check
        return TC_ACT_OK;

    // use bitmask 0x03FF to mask 10-bit ID
    __u16 session_id = bpf_ntohs(erspan->session_id) & 0x03FF;

    // filter by session-ID, 0 means any session-ID
    __u32 key = 0;
    __u16 *filter_id = bpf_map_lookup_elem(&config_map, &key);

    if (filter_id && *filter_id != 0 && session_id != *filter_id) {
        return TC_ACT_OK;
    }

    // calculate bytes to strip by using offsets to keep verifier happy
    __u32 iph_off = (__u32)((void *)iph - data);
    __u32 erspan_off = (__u32)((void *)erspan - data);
    
    // total = (ERSPAN-start - IP-start) + 8B ERSPAN + 14B inner ethernet
    __u32 total_strip_len = (erspan_off - iph_off) + sizeof(struct erspanhdr) + 14;

    // verifier-check
    if (total_strip_len > 128) return TC_ACT_OK;
    if ((void *)iph + total_strip_len > data_end)
        return TC_ACT_OK;

    // remove header, use BPF_F_ADJ_ROOM_FIXED_GSO for jumbo
    if (bpf_skb_adjust_room(skb, -(__s32)total_strip_len, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO)) {
#ifdef DEBUG
        bpf_printk("erspan_decap: ERROR bpf_skb_adjust_room() failed");
#endif
        return TC_ACT_SHOT;
    }

#ifdef DEBUG
    bpf_printk("erspan_decap: ID %d decapsuled, %u bytes removed", session_id, total_strip_len);
#endif

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

