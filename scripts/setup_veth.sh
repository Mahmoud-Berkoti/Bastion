#!/usr/bin/env bash
# Creates (or tears down) a veth pair with one end in a network namespace,
# so XDP can be tested without touching a real NIC.
#
#   host side:  veth-host  10.11.0.1/24   (attach Bastion here)
#   netns side: veth-ns    10.11.0.2/24   (in netns "bastion", traffic source)
set -euo pipefail

NS=bastion
HOST_IF=veth-host
NS_IF=veth-ns
HOST_IP=10.11.0.1/24
NS_IP=10.11.0.2/24

up() {
  ip netns add "$NS" 2>/dev/null || true
  ip link add "$HOST_IF" type veth peer name "$NS_IF" 2>/dev/null || true
  ip link set "$NS_IF" netns "$NS"

  ip addr add "$HOST_IP" dev "$HOST_IF" 2>/dev/null || true
  ip link set "$HOST_IF" up

  ip netns exec "$NS" ip addr add "$NS_IP" dev "$NS_IF" 2>/dev/null || true
  ip netns exec "$NS" ip link set "$NS_IF" up
  ip netns exec "$NS" ip link set lo up

  echo "veth ready: $HOST_IF ($HOST_IP) <-> $NS_IF ($NS_IP) in netns $NS"
  echo "test:  ip netns exec $NS ping -c1 10.11.0.1"
}

down() {
  ip link del "$HOST_IF" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  echo "veth pair and netns removed"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 1 ;;
esac
