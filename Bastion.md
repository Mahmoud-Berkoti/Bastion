# Project Spec: eBPF/XDP Traffic Filter ("Bastion")

> **Instructions for Claude Code:** This document is the single source of truth. Build phase by phase, in order, and do not skip ahead. Every phase must end with all acceptance criteria passing, a git commit (Conventional Commits), and updated docs. The eBPF C code must compile with clang against a pinned kernel headers version and pass the verifier every time. Prefer CO-RE (Compile Once, Run Everywhere) with libbpf and BTF over legacy BCC. If the verifier rejects a program, do NOT silently loosen bounds checks to get past it; explain why it rejected and fix the actual logic. Write the userspace loader/control plane in Go using cilium/ebpf.

---

## 1. Elevator Pitch

Bastion is a high-performance, kernel-level packet filter and network observability tool built on eBPF/XDP. It drops or rate-limits traffic at the earliest possible point in the Linux networking stack (the driver's RX path, before an skb is even allocated), maintains live flow statistics in eBPF maps, and exposes them to a Go control plane that serves a REST API and Prometheus metrics. It supports a declarative rule model (CIDR blocklists, port filters, per-source rate limits) and demonstrates measurable throughput advantages over iptables.

**Why this matters for Cisco:** Cisco's cloud-native and security teams (Secure Workload, their Cilium/Isovalent acquisition in 2023, Calico integration work) build on eBPF for kernel-level packet filtering and observability. eBPF is where high-performance networking is heading industry-wide. Building an XDP data plane with a Go control plane shows you understand the exact technology stack Cilium and Cisco's cloud networking are built on, plus the kernel-level performance engineering that classical iptables cannot match.

## 2. Learning Goals (what Mahmoud must be able to explain afterward)

- What XDP is, where it sits in the stack (driver RX, pre-skb), and why that makes it faster than tc/netfilter/iptables
- The eBPF verifier: bounded loops, memory safety, why it rejects unbounded access, and how CO-RE/BTF work
- eBPF map types (hash, LPM trie, per-CPU array, ring buffer) and when to use each
- XDP actions: XDP_PASS, XDP_DROP, XDP_TX, XDP_REDIRECT, XDP_ABORTED
- The split between the eBPF data plane (in kernel) and the Go control plane (userspace), and how they communicate through maps and ring buffers
- Why per-CPU maps avoid lock contention and how you aggregate them
- How this maps to Cilium's architecture and Cisco's cloud-native security posture

## 3. Tech Stack

| Component | Choice | Rationale |
|---|---|---|
| Data plane | eBPF C compiled with clang, XDP hook | The core of the project |
| Portability | libbpf + CO-RE + BTF | Modern standard, avoids per-kernel recompilation |
| Control plane | Go with cilium/ebpf | Idiomatic, no CGO needed, matches Mahmoud's Go background |
| Testing | Go tests + kernel BPF_PROG_TEST_RUN + packet generators | Unit test XDP programs without real NICs |
| Load generation | pktgen or trafgen or a Scapy/DPDK sender | For throughput benchmarks |
| Observability | Prometheus + Grafana | Standard |
| Environment | Linux kernel 5.15+ (6.x preferred) with BTF enabled | XDP + CO-RE requirement |

**Environment note:** This requires a real Linux kernel with XDP support and `CONFIG_DEBUG_INFO_BTF=y`. Develop on bare-metal Linux, a full VM (multipass/Vagrant Ubuntu 22.04+), or WSL2 with a recent kernel. Containers often will not work because XDP needs a real NIC or at least a veth pair in a namespace you control. Provide a `Vagrantfile` or multipass cloud-init that produces a known-good environment. Test XDP in native mode on a veth pair; document generic (SKB) mode fallback.

## 4. High-Level Architecture

```
   userspace          +------------------------------------+
                       |        Bastion Control Plane (Go)   |
   REST API (:8080) -->|   Rule Manager                     |
   Prometheus (:9090)  |     |          ^                   |
                       |     v          |                   |
                       |  map writers   ring buffer reader  |
                       +-----|----------------|-------------+
   ==========================|================|=================  (syscall boundary)
   kernel                    v                |
                    +--------------------------------------+
                    |   eBPF/XDP program (bastion.bpf.c)    |
                    |                                      |
                    |  parse eth/ip/l4 -> match rules ->   |
                    |  update stats -> XDP_DROP / XDP_PASS |
                    |                                      |
                    |  maps: blocklist(LPM), portrules,    |
                    |        ratelimit(per-CPU), stats,    |
                    |        events(ring buffer)           |
                    +--------------------------------------+
                                    ^
                              packets arrive at NIC/veth RX
```

Core design decisions:

- **Data plane does the minimum:** parse headers with strict bounds checks, look up rules in maps, update counters, return an XDP verdict. No policy logic in the kernel; all policy lives in userspace and is pushed into maps.
- **Control plane owns rules:** the Go process compiles a declarative config into map entries, watches for changes, and reads stats/events back out.
- **Per-CPU maps for counters and rate limiters** to avoid atomics/locks on the hot path; aggregate in userspace.
- **Ring buffer for events** (e.g., "dropped a packet from X matching rule Y") so userspace gets a sampled event stream without polling.

## 5. Repository Layout

```
bastion/
├── bpf/
│   ├── bastion.bpf.c        # the XDP program
│   ├── common.h            # shared structs (packet key, rule, stats)
│   └── vmlinux.h           # generated via bpftool btf dump
├── cmd/bastion/main.go      # control plane entrypoint
├── internal/
│   ├── loader/             # cilium/ebpf load + attach + map handles
│   ├── rules/              # config model -> map entries
│   ├── stats/              # per-CPU aggregation
│   ├── events/             # ring buffer consumer
│   ├── api/                # REST handlers
│   └── metrics/            # Prometheus
├── config/
│   └── rules.yaml          # declarative rules
├── bench/
│   ├── run_pktgen.sh
│   └── compare_iptables.sh # head-to-head benchmark
├── test/
│   └── prog_test/          # BPF_PROG_TEST_RUN based unit tests
├── Vagrantfile
├── Makefile                # clang build, bpftool, go build
└── README.md
```

## 6. Build Phases

### Phase 0: Environment and Toolchain
- Vagrantfile/multipass config producing Ubuntu 22.04+ with clang, llvm, libbpf-dev, bpftool, linux-headers, Go, and BTF enabled.
- `make vmlinux` generates `bpf/vmlinux.h` via `bpftool btf dump file /sys/kernel/btf/vmlinux format c`.
- `make setup-veth` creates a veth pair in a network namespace for safe XDP testing.
- **Acceptance:** `bpftool feature probe` shows XDP support; a trivial XDP program that returns XDP_PASS loads and attaches to the veth without verifier errors.

### Phase 1: Minimal XDP Pass-Through with Packet Parsing
- Write `bastion.bpf.c` that attaches to XDP, parses Ethernet -> IPv4 -> (TCP/UDP/ICMP), with strict bounds checks against `data_end` at every step (the verifier demands this), and returns XDP_PASS.
- Go loader using cilium/ebpf loads the object, attaches to a named interface, and detaches cleanly on exit.
- **Acceptance:** Program attaches to the veth; ping across the veth pair still works (XDP_PASS is transparent); verifier accepts the program; `bpftool prog show` lists it. Unit test via BPF_PROG_TEST_RUN feeding a crafted IPv4/TCP packet and asserting XDP_PASS plus correctly parsed fields written to a debug map.

### Phase 2: Static Drop Rules (CIDR Blocklist via LPM Trie)
- Add an LPM trie map keyed by (prefixlen, IPv4 addr). If the source IP matches, return XDP_DROP.
- Control plane loads a `rules.yaml` blocklist of CIDRs into the LPM map on startup.
- **Acceptance:** Add `10.0.0.5/32` to the blocklist; traffic from that source across the veth is dropped (verify with a counter and with the fact that the receiver sees nothing) while other sources pass. Add `10.0.0.0/24` and confirm prefix matching drops the whole range. Benchmark: this must drop at higher pps than an equivalent `iptables -A INPUT -s ... -j DROP` rule; capture the numbers.

### Phase 3: Port and Protocol Rules + Stats Maps
- Add a hash map of (protocol, port) rules with an action (pass/drop). Match on L4 dest port.
- Add a per-CPU stats map: total packets, total bytes, dropped packets, dropped bytes, per-verdict counters. Increment on every packet.
- Control plane aggregates per-CPU stats and exposes them via `GET /api/v1/stats` and Prometheus.
- **Acceptance:** Block TCP/2222; an ssh/nc attempt to 2222 across the veth fails while 22 works. Stats counters match observed traffic (send N packets with a generator, assert counters == N). Prometheus scrape shows the metrics.

### Phase 4: Per-Source Rate Limiting (Token Bucket in eBPF)
- Implement a token-bucket rate limiter keyed by source IP in a per-CPU hash (or LRU hash to bound memory). Each packet consumes a token; if empty, XDP_DROP. Refill based on bpf_ktime_get_ns() deltas.
- Configurable rate and burst per CIDR from the config.
- **Acceptance:** Set a 1000 pps limit for a source; a generator sending 5000 pps sees roughly 1000 pps pass and the rest dropped (within tolerance). Document the per-CPU accounting caveat (limits are approximate across CPUs) and how Cilium/production systems handle this. This caveat is a great interview talking point.

### Phase 5: Event Streaming via Ring Buffer
- Add a BPF ring buffer. On notable events (drop matching a specific rule, rate-limit trip), emit a compact event record (timestamp, src/dst, verdict, rule id) with sampling to avoid flooding.
- Go control plane consumes the ring buffer in a goroutine and exposes recent events at `GET /api/v1/events` and as a live stream (SSE or websocket).
- **Acceptance:** Trigger drops; events appear in the API within milliseconds; under a flood, sampling keeps the event rate bounded and the ring buffer does not overflow (monitor the discard counter).

### Phase 6: Dynamic Rule Management (Live Reload)
- REST endpoints: `GET/POST/DELETE /api/v1/rules` to add/remove blocklist entries, port rules, and rate limits at runtime by writing map entries, with no reload of the eBPF program.
- Watch `rules.yaml` for changes and reconcile the maps (declarative reconciliation loop, like a mini controller).
- **Acceptance:** Add and remove a blocklist entry via curl while traffic flows; the drop behavior changes within a second with zero packet loss on unaffected flows and no program reload (verify prog id is unchanged).

### Phase 7: Benchmarking and Observability
- `bench/compare_iptables.sh`: run the same drop policy under (a) Bastion XDP, (b) iptables, (c) nftables, using pktgen or trafgen, and record max drop pps and CPU utilization for each.
- Grafana dashboard: pps, drop rate, top blocked sources, rate-limit trips, CPU per core.
- Document XDP native vs generic (SKB) mode performance difference on your test NIC/veth.
- **Acceptance:** A reproducible benchmark report (checked into the repo as `bench/RESULTS.md`) showing XDP dropping meaningfully more pps at lower CPU than iptables, with methodology documented so a Cisco interviewer can trust the numbers.

## 7. Testing Strategy

- **Unit (kernel):** BPF_PROG_TEST_RUN with hand-crafted packets (built with gopacket in Go) asserting the returned XDP verdict and resulting map state for each rule type. This runs in CI without special hardware.
- **Integration:** load the real program onto a veth in a netns, drive traffic with a generator, assert stats and drop behavior.
- **Malformed packet tests:** truncated headers, bad ethertypes, IP options, jumbo frames; the program must never read out of bounds (the verifier enforces this, but test that behavior is correct, not just safe).
- **CI:** GitHub Actions runner with a recent kernel (or a VM action) that builds the BPF object, runs prog-test unit tests, and runs `go vet`/`staticcheck`.

## 8. Security and Safety Notes

- XDP runs in the kernel hot path; a bug can wedge networking on the box. Always test on a veth in a namespace, never on your only NIC without an out-of-band recovery plan.
- Document the trust model: who can push rules, and why arbitrary map writes are equivalent to root-level network control.
- Note that XDP_DROP at the driver is invisible to userspace tcpdump on that interface (tcpdump on the RX path sees packets after XDP for XDP_PASS but drops never reach it in native mode). This surprises people and is worth being able to explain.

## 9. Interview Talking Points (study these, Mahmoud)

- Where XDP sits versus tc versus netfilter/iptables, and why "before skb allocation" is the whole performance story.
- Why the verifier exists and what it guarantees; give a concrete example of a program it rejected and how you fixed it.
- LPM trie vs hash vs per-CPU array vs ring buffer, and why you chose each in this project.
- Per-CPU maps and the lock-free hot path; the accuracy tradeoff in your rate limiter and how production systems mitigate it.
- Your own benchmark numbers: XDP drop pps vs iptables, and the CPU delta.
- How this relates to Cilium (which Cisco/Isovalent build) replacing kube-proxy and iptables with eBPF, and where Cisco Secure Workload uses kernel-level enforcement.
- CO-RE and BTF: how one compiled object runs across kernel versions without recompilation.

## 10. Resume Bullet Targets

- Built a kernel-level packet filter using **eBPF/XDP** and **libbpf CO-RE** with a **Go** control plane (cilium/ebpf), dropping malicious traffic at the driver RX path and sustaining **[X]M pps**, **[Y]x** the drop throughput of iptables at lower CPU.
- Implemented LPM-trie CIDR blocklists, per-source token-bucket rate limiting, and ring-buffer event streaming across the kernel/userspace boundary, with live declarative rule reconciliation and zero program reloads.
- Validated data-plane correctness with **BPF_PROG_TEST_RUN** unit tests over crafted and malformed packets, wired into **CI**, ensuring verifier-safe bounds handling on every path.

*(Fill in [X], [Y] from your actual benchmark. Real numbers you can defend beat vague claims.)*

## 11. Resources

- "BPF Performance Tools" and the BPF/XDP chapters (Brendan Gregg)
- cilium/ebpf library docs and examples (the Go loader canon)
- libbpf-bootstrap repo (CO-RE project scaffolding to mirror)
- kernel docs: Documentation/bpf/, and the XDP tutorial at github.com/xdp-project/xdp-tutorial
- Cilium docs on eBPF datapath (read to connect your project to Cisco's acquisition)
