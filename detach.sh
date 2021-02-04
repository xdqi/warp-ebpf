#!/bin/bash -e

tc qdisc del dev "$1" clsact
