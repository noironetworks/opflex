#!/bin/sh
# Usage: ./init.sh <dev> <obj> <ingress|egress> <sec>
set -x

DEV=$1
OBJ=$2
DIR=$3
SEC=$4

tc qdisc replace dev $DEV clsact &&
tc filter add dev $DEV $DIR bpf da obj $OBJ sec $SEC &&
tc filter show dev $DEV $DIR
