// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define SMELLY_PORT 0x1919

static inline int hack_ip_proto(struct __sk_buff *skb, __u8 from, __u8 to) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (skb->protocol != __constant_htons(ETH_P_IP))
    return TC_ACT_UNSPEC;

  __u32 net_offset = 0;
  struct ethhdr *eth = data;
  // Sorry Level 3 (8.0.0.0/16)
  if (eth->h_proto == skb->protocol) {
    net_offset = sizeof(struct ethhdr);
  }

  size_t min_packet_size = net_offset + sizeof(struct iphdr) + sizeof(struct udphdr);
  if (data + min_packet_size >= data_end)
    return TC_ACT_UNSPEC;

  struct iphdr *ip = data + net_offset;
  struct udphdr *udp = data + net_offset + sizeof(struct iphdr);

  if (ip->version != IPVERSION)
    return TC_ACT_UNSPEC;
  if (ip->protocol != from)
    return TC_ACT_UNSPEC;

  /* offsetof(struct udphdr, dest) == offsetof(struct icmphdr, type), and ICMP
   * type 0x19 is reserved, so it is reasonably safe to assume these might be
   * faked UDP packets even on ingress and always match on udp->dest */
  if (udp->dest != __constant_ntohs(SMELLY_PORT))
    return TC_ACT_UNSPEC;

  ip->protocol = to;
  bpf_l3_csum_replace(skb,
                      net_offset + offsetof(struct iphdr, check),
                      /* offsetof(struct iphdr, protocol) % 2 == 1 */
                      (from << 8), (to << 8), 2);
  return TC_ACT_PIPE;
}

/* should be used with direct-action flag */
SEC("ingress")
int turn_camouflaged_icmp_into_udp(struct __sk_buff *skb) {
  return hack_ip_proto(skb, IPPROTO_ICMP, IPPROTO_UDP);
}

SEC("egress")
int turn_udp_into_camouflaged_icmp(struct __sk_buff *skb) {
  return hack_ip_proto(skb, IPPROTO_UDP, IPPROTO_ICMP);
}
