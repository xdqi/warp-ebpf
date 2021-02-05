What
--------------------------

A tc-bpf action to rewrite `ip->protocol` to ICMP for outgoing UDP packets with dest port = 0x1919, and vice versa for ingress.

Jesus Why?
--------------------------

* Your ISP have an interesting "management network" connecting all subscribers in the city.
* They block all traffic between subscribers, except when `ip->protocol = 1`.
* You want to have fun with your friend. (and discover that the link is throttled to 20Mbps)
* You heard that in 2021 there are 114514 eBPF hook points in kernel but never tried any one of them thus want a toy example slightly more complex than hello world.
