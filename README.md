# Bastion

A kernel-level packet filter built on **eBPF/XDP**. It drops or rate-limits traffic at the NIC's RX path before the kernel allocates an skb, and exposes live flow statistics through a Go control plane, REST API, web dashboard, and Prometheus metrics.

```
   userspace          +------------------------------------+
                      |     Control Plane (Go)              |
   dashboard + REST ->|   Rule Manager                      |
   (:8080)            |     |          ^                    |
   Prometheus (:9090) |     v          |                    |
                      |  map writers   ring buffer reader   |
                      +-----|----------------|--------------+
   =========================|================|===============  (syscall boundary)
   kernel                   v                |
                   +--------------------------------------+
                   |   XDP program (bastion.bpf.c)        |
                   |  parse eth/ip/l4 -> match rules ->   |
                   |  update stats -> XDP_DROP / XDP_PASS |
                   |  maps: blocklist(LPM), port_rules,   |
                   |        rate_state(per-CPU), stats,   |
                   |        events(ring buffer)           |
                   +--------------------------------------+
                                   ^
                        packets arrive at NIC/veth RX
```

## What it does

- **CIDR blocklist** — drops traffic from specified source addresses using LPM-trie longest-prefix matching
- **Port/protocol rules** — blocks or passes traffic by destination port and protocol
- **Per-source rate limiting** — token buckets in a per-CPU LRU hash, configured per CIDR, refilled using kernel nanosecond timestamps
- **Live stats** — per-CPU counters aggregated in userspace, served at `/api/v1/stats` and as Prometheus metrics
- **Event streaming** — sampled drop events from a BPF ring buffer, exposed over REST and Server-Sent Events
- **Declarative rules** — `config/rules.yaml` is watched and reconciled into BPF maps without restarting the program; the REST API mutates the same state live
- **Web dashboard** — embedded in the binary, no build step: live throughput sparkline, drop breakdown by rule type, rule management forms, and a streaming event feed

## Requirements

Linux kernel 5.15+ with `CONFIG_DEBUG_INFO_BTF=y`. On macOS or Windows use the included Vagrant VM:

```sh
vagrant up && vagrant ssh
cd bastion
```

## Build

```sh
make all         # generates vmlinux.h, compiles BPF object, builds Go binary
make setup-veth  # creates a veth pair in a network namespace for safe testing
```

## Run

```sh
sudo ./bin/bastion -iface veth-host -config config/rules.yaml
```

Open `http://localhost:8080` for the dashboard (port is forwarded from the VM).

**Demo mode** (macOS/any platform, no kernel required):

```sh
make demo   # serves the dashboard with synthetic data at localhost:8080
```

## Usage examples

```sh
# ping across the veth — passes by default
sudo ip netns exec bastion ping -c3 10.11.0.1

# blocked port (defined in config/rules.yaml)
sudo ip netns exec bastion nc -zvw1 10.11.0.1 2222

# block a source live — no program reload
curl -XPOST localhost:8080/api/v1/rules \
  -d '{"type":"blocklist","cidr":"10.11.0.2/32"}'

# remove it
curl -XDELETE localhost:8080/api/v1/rules \
  -d '{"type":"blocklist","cidr":"10.11.0.2/32"}'
```

## REST API

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/status` | interface, attach mode, BPF program id |
| GET | `/api/v1/stats` | aggregated packet/byte/drop counters |
| GET | `/api/v1/rules` | active rule set |
| POST | `/api/v1/rules` | add a rule |
| DELETE | `/api/v1/rules` | remove a rule |
| GET | `/api/v1/events?limit=N` | recent drop events |
| GET | `/api/v1/events/stream` | live drop events (SSE) |

Rule request bodies:

```json
{"type":"blocklist","cidr":"10.0.0.5/32"}
{"type":"port","proto":"tcp","port":2222,"action":"drop"}
{"type":"ratelimit","cidr":"10.0.0.0/24","pps":1000,"burst":200}
```

Prometheus metrics on `:9090/metrics`.

## Testing

```sh
make test   # go vet + BPF_PROG_TEST_RUN unit tests (requires root, no NIC needed)
```

Tests run the real XDP program in the kernel against hand-crafted packets covering: header parsing, LPM prefix matching, port rules, stats counters, token-bucket rate limiting, and malformed/truncated packet handling.

## Benchmarks

```sh
make bench   # writes bench/RESULTS.md
```

Runs the same drop policy under Bastion/XDP, iptables, and nftables using kernel pktgen, and records sustained packet rate and CPU usage for each.

## Repository layout

```
bpf/               XDP program and shared struct definitions
cmd/bastion/       control plane entrypoint
cmd/bastion-demo/  demo mode entrypoint (no kernel required)
internal/loader/   BPF object loading and XDP attach
internal/rules/    declarative config to BPF map reconciliation
internal/stats/    per-CPU counter aggregation
internal/events/   ring buffer consumer and event fan-out
internal/api/      REST API, SSE stream, embedded web dashboard
internal/metrics/  Prometheus collector
config/rules.yaml  declarative rules file
bench/             throughput benchmarks
test/prog_test/    BPF_PROG_TEST_RUN unit tests
```

## Notes

- Packets dropped in XDP native mode are not visible to `tcpdump` on the same interface — use the `/api/v1/events/stream` endpoint to observe drops instead.
- Rate-limit buckets are per-CPU, so limits are approximate when a flow is spread across multiple CPUs by RSS.
- The API binds to localhost by default. Add authentication before exposing it on a network.
