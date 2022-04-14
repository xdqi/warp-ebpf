#!/bin/bash -e

[ -f "1919.o" ] || exit 1

tc qdisc add dev "$1" clsact
tc filter add dev "$1" egress bpf direct-action obj 1919.o section egress
tc filter add dev "$1" ingress bpf direct-action obj 1919.o section ingress

LOWER_IF="`(basename $(realpath $(ls -d /sys/class/net/$1/lower_*)) || echo $1)2>/dev/null`"
# ethtool -K "$LOWER_IF" tx off || true
