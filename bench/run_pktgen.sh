#!/usr/bin/env bash
# Drives the kernel pktgen module to flood the veth pair from inside the
# "bastion" netns toward the host side, where the filter under test runs.
#
# usage: run_pktgen.sh <src_ip> <dst_ip> <duration_s> [pkt_size]
# Requires: modprobe pktgen, scripts/setup_veth.sh up
set -euo pipefail

SRC_IP=${1:?src ip}
DST_IP=${2:?dst ip}
DURATION=${3:?duration seconds}
PKT_SIZE=${4:-64}

NS=bastion
DEV=veth-ns
# pktgen needs the peer's MAC as the L2 destination.
DST_MAC=$(cat /sys/class/net/veth-host/address)

modprobe pktgen

pgset() {
  local dev_file=$1 cmd=$2
  ip netns exec "$NS" sh -c "echo '$cmd' > $dev_file"
}

# pktgen threads live per-netns via /proc after moving the device; simplest
# reliable setup is to run pktgen against the netns device from within it.
THREAD=/proc/net/pktgen/kpktgend_0
PGDEV=/proc/net/pktgen/$DEV

ip netns exec "$NS" sh -c "echo 'rem_device_all' > $THREAD"
ip netns exec "$NS" sh -c "echo 'add_device $DEV' > $THREAD"

pgset "$PGDEV" "count 0"            # run until stopped
pgset "$PGDEV" "clone_skb 1000"     # amortize skb allocation on the sender
pgset "$PGDEV" "pkt_size $PKT_SIZE"
pgset "$PGDEV" "delay 0"
pgset "$PGDEV" "src_min $SRC_IP"
pgset "$PGDEV" "src_max $SRC_IP"
pgset "$PGDEV" "dst $DST_IP"
pgset "$PGDEV" "dst_mac $DST_MAC"

echo "pktgen: $SRC_IP -> $DST_IP for ${DURATION}s (pkt_size $PKT_SIZE)"
ip netns exec "$NS" sh -c "echo start > /proc/net/pktgen/pgctrl" &
PGPID=$!
sleep "$DURATION"
ip netns exec "$NS" sh -c "echo stop > /proc/net/pktgen/pgctrl" || true
wait "$PGPID" 2>/dev/null || true

# Report sender-side numbers (packets actually put on the wire).
ip netns exec "$NS" grep -A2 'Result:' "$PGDEV" || ip netns exec "$NS" cat "$PGDEV"
