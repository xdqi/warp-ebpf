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

char LICENSE[] SEC("license") = "GPL";

static inline int rewrite_wg_reserved_ipv4(struct __sk_buff *skb,
        struct sockaddr_in *endpoint, bool endpoint_is_source,
        const __u8 from[], const __u8 to[]) {
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

    if ((endpoint_is_source && iph->saddr == endpoint->sin_addr.s_addr && udph->source == endpoint->sin_port) ||
        (!endpoint_is_source && iph->daddr == endpoint->sin_addr.s_addr && udph->dest == endpoint->sin_port)) {
        // should be __builtin_memcmp(wg_header + 1, from, 3)
        // but https://bugs.llvm.org/show_bug.cgi?id=26218 prevents this
        if (wg_header[1] != from[0] ||
            wg_header[2] != from[1] ||
            wg_header[3] != from[2]) {
            return TC_ACT_UNSPEC;
        }

        __u8 old_wgh[4];
        __builtin_memcpy(old_wgh, wg_header, 4);

        __builtin_memcpy(wg_header + 1, to, 3);

        // ignore udp checksum as wireguard protocol has its own check
//        udph->check = 0;
        return TC_ACT_PIPE;
    }
    return TC_ACT_UNSPEC;
}

// configuration
static const __u8 wg_reserved[3] = {0x00, 0x00, 0x00};
static const __u8 warp_private[3] = {11, 45, 14};
static struct sockaddr_in endpoint = {
        .sin_family = AF_INET,
        .sin_addr = {
                // 162.159.192.1 is the IPv4 address of engage.cloudflareclient.com
                .s_addr = __bpf_constant_htonl(0xa29fc001),
        },
        .sin_port = __bpf_constant_htons(2408)
};

SEC("ingress")
int convert_to_original_wireguard(struct __sk_buff *skb) {
    return rewrite_wg_reserved_ipv4(skb, &endpoint, true, warp_private, wg_reserved);
}

SEC("egress")
int convert_to_cloudflare_warp(struct __sk_buff *skb) {
    return rewrite_wg_reserved_ipv4(skb, &endpoint, false, wg_reserved, warp_private);
}
