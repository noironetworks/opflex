#!/bin/sh
# Usage: ./check.sh <obj> <ingress|egress> <sec>
set -x

DEV="dummy"
OBJ=$1
DIR=$2
SEC=$3

ip link del $DEV 2>/dev/null
ip link add $DEV type dummy || exit 1
tc qdisc del dev $DEV clsact 2>/dev/null

tc qdisc add dev $DEV clsact &&
tc filter add dev $DEV $DIR bpf da obj $OBJ sec $SEC &&
tc filter show dev $DEV $DIR &&
ip link del $DEV 2>/dev/null
