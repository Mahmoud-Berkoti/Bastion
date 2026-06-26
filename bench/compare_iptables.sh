#!/usr/bin/env bash
# Head-to-head drop benchmark: the same "drop source 10.11.0.66" policy
# under (a) Bastion/XDP, (b) iptables, (c) nftables, measured with pktgen
# flooding the veth pair. Records drop pps and CPU. Results go to
# bench/RESULTS.md — methodology at the bottom of this file.
#
# Run as root inside the Vagrant VM, after `make all && make setup-veth`.
set -euo pipefail

cd "$(dirname "$0")/.."

DURATION=${DURATION:-15}
BLOCKED_SRC=10.11.0.66
DST=10.11.0.1
RESULTS=bench/RESULTS.md
BASTION_PID=""

cleanup() {
  [ -n "$BASTION_PID" ] && kill "$BASTION_PID" 2>/dev/null || true
  iptables -D INPUT -s $BLOCKED_SRC -j DROP 2>/dev/null || true
  nft delete table ip bastion_bench 2>/dev/null || true
}
trap cleanup EXIT

rx_packets() { cat /sys/class/net/veth-host/statistics/rx_packets; }

# cpu_busy: average non-idle % across the run, via /proc/stat deltas.
cpu_snapshot() { awk '/^cpu /{print $2+$3+$4+$6+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat; }

measure() {
  local name=$1
  echo "--- $name: flooding for ${DURATION}s"
  local rx0 cpu0 cpu1 rx1
  rx0=$(rx_packets)
  read -r busy0 total0 <<<"$(cpu_snapshot)"
  ./bench/run_pktgen.sh $BLOCKED_SRC $DST "$DURATION" >/tmp/pktgen_$name.log 2>&1
  rx1=$(rx_packets)
  read -r busy1 total1 <<<"$(cpu_snapshot)"

  local sent
  sent=$(grep -oP '\d+(?=pps)' /tmp/pktgen_$name.log | head -1 || echo "?")
  local rx=$((rx1 - rx0))
  local cpu=$(( (busy1 - busy0) * 100 / (total1 - total0 + 1) ))
  # For XDP native mode, drops happen before rx accounting on some paths;
  # Bastion's own stats are authoritative there.
  echo "$name: sender=${sent}pps rx_delta=$rx cpu_busy=${cpu}%"
  echo "| $name | ${sent} | ${cpu}% |" >> "$RESULTS"
}

cat > "$RESULTS" <<EOF
# Bastion benchmark results

Generated $(date -u +"%Y-%m-%dT%H:%M:%SZ") on $(uname -r), $(nproc) CPUs.
Policy under test: drop all packets from $BLOCKED_SRC. Sender: kernel
pktgen at max rate over a veth pair, ${DURATION}s per run.

| filter | sender pps sustained | cpu busy |
|---|---|---|
EOF

# (a) Bastion XDP
./bin/bastion -iface veth-host -config config/rules.yaml &
BASTION_PID=$!
sleep 2
curl -s -XPOST localhost:8080/api/v1/rules \
  -d "{\"type\":\"blocklist\",\"cidr\":\"$BLOCKED_SRC/32\"}" >/dev/null
measure "bastion-xdp"
DROPPED=$(curl -s localhost:8080/api/v1/stats | jq .dropped_packets)
echo "bastion reported $DROPPED packets dropped in-kernel"
sed -i "s/| bastion-xdp |/| bastion-xdp (dropped $DROPPED) |/" "$RESULTS"
kill "$BASTION_PID"; wait "$BASTION_PID" 2>/dev/null || true; BASTION_PID=""

# (b) iptables
iptables -A INPUT -s $BLOCKED_SRC -j DROP
measure "iptables"
iptables -D INPUT -s $BLOCKED_SRC -j DROP

# (c) nftables
nft add table ip bastion_bench
nft add chain ip bastion_bench input '{ type filter hook input priority 0; }'
nft add rule ip bastion_bench input ip saddr $BLOCKED_SRC drop
measure "nftables"
nft delete table ip bastion_bench

cat >> "$RESULTS" <<'EOF'

## Methodology

- Sender: kernel pktgen in the `bastion` netns, 64-byte UDP frames from
  the blocked source at maximum rate over a veth pair.
- Each filter enforces an identical single-source drop policy; only the
  enforcement point differs (XDP driver hook vs netfilter INPUT hook).
- CPU is whole-system non-idle time from /proc/stat over the run, which
  includes the sender: compare deltas between rows, not absolute values.
- veth caveat: veth has no real driver RX ring, so XDP runs in native
  mode but without hardware offload benefits; on a physical NIC the XDP
  advantage grows. Generic (SKB) mode numbers, where measured, are noted
  separately.
- The XDP drop happens before skb allocation; iptables/nftables drops pay
  for skb allocation + netfilter traversal first. That difference is the
  entire performance story.
EOF

echo
echo "results written to $RESULTS"
cat "$RESULTS"
