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

/* should be used with direct-action flag */
SEC("classifier")
int turn_udp_into_camouflaged_icmp(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  size_t min_packet_size =
      sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
  if (data + min_packet_size >= data_end)
    return TC_ACT_UNSPEC;

  struct ethhdr *eth = data;
  struct iphdr *ip = (data + sizeof(struct ethhdr));
  struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

  if (eth->h_proto != __constant_htons(ETH_P_IP))
    return TC_ACT_UNSPEC;
  if (ip->protocol != IPPROTO_UDP)
    return TC_ACT_UNSPEC;

  if (udp->dest != __constant_ntohs(SMELLY_PORT))
    return TC_ACT_UNSPEC;
  
  __u8 new_proto = IPPROTO_ICMP;
  bpf_skb_store_bytes(skb,
                      sizeof(struct ethhdr) + offsetof(struct iphdr, protocol),
                      &new_proto, sizeof(new_proto), 0);
  bpf_l3_csum_replace(skb,
                      sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                      IPPROTO_UDP, IPPROTO_ICMP, 2);
  return TC_ACT_PIPE;
}
