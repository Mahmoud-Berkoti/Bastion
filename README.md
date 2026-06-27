# Bastion

Kernel-level packet filter and network observability tool built on
**eBPF/XDP**. Bastion drops or rate-limits traffic at the driver RX path —
before the kernel even allocates an skb — and exposes live flow statistics
through a Go control plane with a REST API, a web dashboard, and
Prometheus metrics.

```
   userspace          +------------------------------------+
                      |     Bastion Control Plane (Go)      |
   dashboard + REST ->|   Rule Manager                      |
   (:8080)            |     |          ^                    |
   Prometheus (:9090) |     v          |                    |
                      |  map writers   ring buffer reader   |
                      +-----|----------------|--------------+
   =========================|================|===============  (syscall boundary)
   kernel                   v                |
                   +--------------------------------------+
                   |   eBPF/XDP program (bastion.bpf.c)   |
                   |  parse eth/ip/l4 -> match rules ->   |
                   |  update stats -> XDP_DROP / XDP_PASS |
                   |  maps: blocklist(LPM), port_rules,   |
                   |        rate_state(per-CPU), stats,   |
                   |        events(ring buffer)           |
                   +--------------------------------------+
                                   ^
                        packets arrive at NIC/veth RX
```

**Design split:** the data plane (kernel) does the minimum — bounds-checked
header parsing, map lookups, counter updates, verdict. All policy lives in
userspace and is pushed into maps; rule changes never reload the program.

## Features

- **CIDR blocklist** — LPM-trie longest-prefix match on source address
- **Port/protocol rules** — hash-map lookup on (proto, dst port)
- **Per-source rate limiting** — token buckets in a per-CPU LRU hash,
  refilled from `bpf_ktime_get_ns()` deltas, configured per CIDR
- **Live stats** — per-CPU counters aggregated in userspace, served at
  `/api/v1/stats` and as Prometheus metrics
- **Event streaming** — sampled drop events over a BPF ring buffer,
  exposed via REST and Server-Sent Events
- **Declarative rules** — `config/rules.yaml` is watched and reconciled
  into the maps live (a miniature controller); the REST API mutates the
  same desired state
- **Web dashboard** — a minimal, dependency-free frontend embedded in the
  binary: live throughput sparkline, drop breakdown, rule management, and
  a streaming event feed at `http://localhost:8080`

## Quick start

Bastion needs a Linux kernel (5.15+, BTF enabled). On macOS/Windows, use
the provided VM:

```sh
vagrant up && vagrant ssh
cd bastion
make all          # vmlinux.h -> clang BPF object -> Go binary
make setup-veth   # veth pair in a netns: safe XDP playground
sudo ./bin/bastion -iface veth-host -config config/rules.yaml
```

Then open http://localhost:8080 (forwarded to the host) and generate some
traffic:

```sh
# passes (10.11.0.2 is not blocked)
sudo ip netns exec bastion ping -c3 10.11.0.1

# blocked port from config/rules.yaml
sudo ip netns exec bastion nc -zvw1 10.11.0.1 2222

# block a source live, no reload
curl -XPOST localhost:8080/api/v1/rules \
  -d '{"type":"blocklist","cidr":"10.11.0.2/32"}'
sudo ip netns exec bastion ping -c3 10.11.0.1   # now 100% loss
```

## REST API

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/status` | iface, attach mode, prog id |
| GET | `/api/v1/stats` | aggregated data-plane counters |
| GET | `/api/v1/rules` | active rule set |
| POST | `/api/v1/rules` | add a rule (see below) |
| DELETE | `/api/v1/rules` | remove a rule (same body shape) |
| GET | `/api/v1/events?limit=N` | recent drop events |
| GET | `/api/v1/events/stream` | live events (SSE) |

Rule bodies:

```json
{"type":"blocklist","cidr":"10.0.0.5/32"}
{"type":"port","proto":"tcp","port":2222,"action":"drop"}
{"type":"ratelimit","cidr":"10.0.0.0/24","pps":1000,"burst":200}
```

Prometheus metrics are on `:9090/metrics` (`bastion_packets_total`,
`bastion_drop_blocklist_total`, …).

## Testing

```sh
make test    # go vet + BPF_PROG_TEST_RUN unit tests (root, no NIC needed)
```

The unit tests execute the real XDP program in the kernel against packets
crafted with gopacket: parse correctness, LPM prefix matching, port rules,
counter accuracy, token-bucket behavior, and malformed-packet handling
(truncated headers, bad IHL, non-IP ethertypes). The verifier proves the
program can't read out of bounds; the tests prove the behavior is also
*correct* — e.g. a truncated TCP header degrades to port-less matching
instead of letting a blocklisted source through.

Integration testing: `make setup-veth`, attach, drive traffic with
ping/nc/pktgen, and assert via `/api/v1/stats`.

## Benchmarks

```sh
make bench   # writes bench/RESULTS.md
```

`bench/compare_iptables.sh` runs the identical single-source drop policy
under Bastion/XDP, iptables, and nftables, flooding with kernel pktgen
over the veth pair, and records sustained pps and CPU. Methodology is
appended to the results file so the numbers are reproducible.

## Design notes & caveats (the interview section)

- **Why XDP is fast:** the hook runs in the driver's RX path before skb
  allocation. An iptables drop pays for skb allocation plus netfilter
  traversal first; an XDP_DROP recycles the DMA buffer immediately.
  That's the entire performance story.
- **Verifier discipline:** every header access is bounds-checked against
  `data_end`, including the recomputed L4 offset when IPv4 options are
  present (`ihl > 5`). If the verifier rejects a change, the logic is
  wrong — the fix is never to loosen a check.
- **Map choices:** LPM trie for CIDRs (longest-prefix semantics for free),
  hash for exact (proto, port) keys, per-CPU array for hot-path counters
  (no atomics, summed in userspace), LRU per-CPU hash for rate-limiter
  state (bounded memory under source floods), ring buffer for events
  (single shared buffer, epoll-driven consumer, cheaper than perf buffers).
- **Rate-limit accuracy:** buckets are per-CPU, so a flow spread across N
  CPUs by RSS can pass up to N× the configured rate in the worst case.
  This is the standard lock-free tradeoff; production systems (e.g.
  Cilium's bandwidth manager) either accept it, shard the rate by CPU, or
  pay for shared state with atomics.
- **Event sampling:** the kernel emits every Nth drop (per CPU,
  `-event-sample-rate`), and ring-buffer reserve failures are counted
  (`bastion_event_drops_total`), so a flood can't wedge the event path.
- **Fail-open:** unparseable and non-IPv4 traffic passes. A filter that
  can't classify a packet must not break ARP or IPv6 connectivity.
  IP-level rules still apply when only the L4 header is truncated.
- **tcpdump surprise:** packets dropped by XDP in native mode never reach
  the capture path — tcpdump on the protected interface won't see them.
  Use Bastion's own event stream to observe drops.
- **Trust model:** whoever can write these maps (or reach the API)
  controls the box's network path — equivalent to root-level network
  control. The API binds locally by default and has no auth; front it
  with real authentication before exposing it.

## Repository layout

```
bpf/                  XDP program + shared struct layouts (CO-RE, libbpf)
cmd/bastion/          control plane entrypoint
internal/loader/      load, verify, attach (native -> generic fallback)
internal/rules/       yaml/API desired state -> map reconciliation
internal/stats/       per-CPU aggregation
internal/events/      ring buffer consumer + fan-out hub
internal/api/         REST + SSE + embedded web dashboard
internal/metrics/     Prometheus collector
config/rules.yaml     declarative rules (watched, hot-reloaded)
bench/                pktgen + iptables/nftables comparison
test/prog_test/       BPF_PROG_TEST_RUN unit tests
```
