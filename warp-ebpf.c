// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "config.h"

char LICENSE[] SEC("license") = "GPL";

// i'd like to use __builtin_memcmp or even memcmp
// but https://bugs.llvm.org/show_bug.cgi?id=26218 prevents this
static inline int bpf_memcmp(const void *s1, const void *s2, size_t n) {
    const __u8* u1 = s1, *u2 = s2;
    for (; --n; ++u1, ++u2) {
        if (*u1 != *u2) {
            return *u1 - *u2;
        }
    }
    return 0;
}

static inline int rewrite_wg_reserved_ipv4(struct __sk_buff *skb, struct warp_conversion *conv) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (skb->protocol != __constant_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    __u32 net_offset = 0;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) <= data_end && eth->h_proto == skb->protocol) {
        net_offset = sizeof(struct ethhdr);
    }

    __u32 prot_offset = net_offset + sizeof(struct iphdr);

    // we just check if udp message contains wg reserved_zero bytes
    size_t min_packet_size = net_offset + sizeof(struct iphdr) + sizeof(struct udphdr) + 4;
    if (data + min_packet_size > data_end)
        return TC_ACT_UNSPEC;

    struct iphdr *iph = data + net_offset;
    struct udphdr *udph = data + net_offset + sizeof(struct iphdr);
    __u32 message_offset = net_offset + sizeof(struct iphdr) + sizeof(struct udphdr);
    __u8 *wg_header = data + message_offset;

    if (iph->version != IPVERSION || iph->protocol != IPPROTO_UDP)
        return TC_ACT_UNSPEC;

    for (struct warp_conversion *i = conv; bpf_memcmp(i->warp_private, wg_reserved, 3); ++i) {
        if (iph->saddr == i->endpoint.sin_addr.s_addr && udph->source == i->endpoint.sin_port) {
            if (i->is_source && !bpf_memcmp(wg_reserved, wg_header + 1, 3)) {
                __builtin_memcpy(wg_header + 1, i->warp_private, 3);
                return TC_ACT_PIPE;
            } else if (!i->is_source && !bpf_memcmp(i->warp_private, wg_header + 1, 3)) {
                __builtin_memcpy(wg_header + 1, wg_reserved, 3);
                return TC_ACT_PIPE;
            }
        } else if (iph->daddr == i->endpoint.sin_addr.s_addr && udph->dest == i->endpoint.sin_port) {
            if (i->is_source && !bpf_memcmp(i->warp_private, wg_header + 1, 3)) {
                __builtin_memcpy(wg_header + 1, wg_reserved, 3);
                return TC_ACT_PIPE;
            } else if (!i->is_source && !bpf_memcmp(wg_reserved, wg_header + 1, 3)) {
                __builtin_memcpy(wg_header + 1, i->warp_private, 3);
                return TC_ACT_PIPE;
            }
        }
    }

    return TC_ACT_UNSPEC;
}

SEC("warp")
int conversion(struct __sk_buff *skb) {
    return rewrite_wg_reserved_ipv4(skb, config);
}
