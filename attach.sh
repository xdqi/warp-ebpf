#!/bin/bash -e

[ -f "1919-ingress.o" ] || exit 1
[ -f "1919-egress.o" ] || exit 1

tc qdisc add dev "$1" clsact
tc filter add dev "$1" egress bpf direct-action obj 1919-egress.o
tc filter add dev "$1" ingress bpf direct-action obj 1919-ingress.o
