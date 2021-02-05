#!/bin/bash -e

tc qdisc del dev "$1" clsact
LOWER_IF="`(basename $(realpath $(ls -d /sys/class/net/$1/lower_*)) || echo $1)2>/dev/null`"
ethtool -K "$LOWER_IF" tx on || true
