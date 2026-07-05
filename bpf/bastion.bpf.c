// SPDX-License-Identifier: GPL-2.0
/* Bastion XDP data plane.
 *
 * Design: the kernel side does the minimum — parse headers with strict
 * bounds checks, look up rules in maps, update per-CPU counters, return a
 * verdict. All policy lives in userspace and is pushed into these maps.
 *
 * Unparseable or non-IPv4 traffic fails open (XDP_PASS): a packet filter
 * that can't classify a packet should not silently break ARP/IPv6/etc.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800

/* One token == TOKEN_SCALE fixed-point units, so refill math keeps
 * sub-token precision between packets. */
#define TOKEN_SCALE 1000000ULL

/* Patched by the loader before load. 1 == emit an event for every drop;
 * N == emit every Nth drop (per CPU). */
const volatile __u32 event_sample_rate = 1;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, __u32); /* rule id */
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct port_rule_key);
	__type(value, struct port_rule_val);
	__uint(max_entries, 1024);
} port_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, struct rate_cfg);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} rate_cfgs SEC(".maps");

/* Token bucket state per source IP. LRU bounds memory under source-IP
 * floods; per-CPU keeps the hot path lock-free. The tradeoff: each CPU
 * runs an independent bucket, so the effective aggregate limit is
 * approximate (up to rate * nr_cpus worst case with perfect RSS spread).
 * Documented in the README; Cilium et al. accept the same tradeoff or
 * shard rates per CPU. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, __u32); /* saddr */
	__type(value, struct bastion_token_bucket);
	__uint(max_entries, 16384);
} rate_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct stats);
	__uint(max_entries, 1);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Per-CPU drop sequence number driving event sampling. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} event_seq SEC(".maps");

/* Only read by BPF_PROG_TEST_RUN unit tests to assert parsed fields. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct pkt_view);
	__uint(max_entries, 1);
} debug_last SEC(".maps");

static __always_inline struct stats *get_stats(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&stats_map, &key);
}

static __always_inline void emit_event(__u32 saddr, __u32 daddr,
				       __u16 sport, __u16 dport,
				       __u8 proto, __u8 reason, __u32 rule_id)
{
	__u32 zero = 0;
	__u64 *seq = bpf_map_lookup_elem(&event_seq, &zero);
	if (!seq)
		return;
	__u64 n = *seq;
	*seq = n + 1;
	if (event_sample_rate > 1 && n % event_sample_rate != 0)
		return;

	struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		struct stats *st = get_stats();
		if (st)
			st->event_drops++;
		return;
	}
	ev->ts_ns = bpf_ktime_get_ns();
	ev->saddr = saddr;
	ev->daddr = daddr;
	ev->sport = sport;
	ev->dport = dport;
	ev->proto = proto;
	ev->reason = reason;
	ev->pad = 0;
	ev->rule_id = rule_id;
	ev->pad2 = 0;
	bpf_ringbuf_submit(ev, 0);
}

/* Returns 1 if the packet exceeds the source's token bucket and must drop.
 * Refill math: tokens are scaled by TOKEN_SCALE (1e6), so
 * refill_scaled = delta_ns * pps * 1e6 / 1e9 = (delta_ns / 1000) * pps.
 * Dividing delta first keeps the multiply far from u64 overflow even for
 * long idle gaps at high rates. */
static __always_inline int rate_limit_exceeded(__u32 saddr,
					       const struct rate_cfg *cfg)
{
	__u64 now = bpf_ktime_get_ns();
	__u64 max_tokens = cfg->burst * TOKEN_SCALE;

	struct bastion_token_bucket *tb = bpf_map_lookup_elem(&rate_state, &saddr);
	if (!tb) {
		struct bastion_token_bucket fresh = { .last_ns = now };
		if (max_tokens >= TOKEN_SCALE) {
			fresh.tokens = max_tokens - TOKEN_SCALE; /* spend one */
			bpf_map_update_elem(&rate_state, &saddr, &fresh, BPF_ANY);
			return 0;
		}
		bpf_map_update_elem(&rate_state, &saddr, &fresh, BPF_ANY);
		return 1; /* burst of 0: nothing to spend */
	}

	__u64 delta = now - tb->last_ns;
	__u64 tokens = tb->tokens + (delta / 1000) * cfg->rate_pps;
	if (tokens > max_tokens)
		tokens = max_tokens;
	tb->last_ns = now;

	if (tokens >= TOKEN_SCALE) {
		tb->tokens = tokens - TOKEN_SCALE;
		return 0;
	}
	tb->tokens = tokens;
	return 1;
}

SEC("xdp")
int bastion_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 pkt_len = (__u64)(data_end - data);

	struct stats *st = get_stats();
	if (st) {
		st->total_pkts++;
		st->total_bytes += pkt_len;
	}

	/* L2: every pointer advance is bounds-checked against data_end —
	 * the verifier rejects the program otherwise, and rightly so. */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		goto pass;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		goto pass;

	/* L3 */
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		goto pass;
	if (iph->ihl < 5)
		goto pass; /* malformed */
	/* IP options: recompute L4 offset from the real header length and
	 * re-check bounds before touching anything past the fixed header. */
	void *l4 = (void *)iph + iph->ihl * 4;
	if (l4 > data_end)
		goto pass;

	__u32 saddr = iph->saddr;
	__u32 daddr = iph->daddr;
	__u8 proto = iph->protocol;
	__u16 sport = 0, dport = 0;
	int has_l4 = 0;

	/* A truncated L4 header must not bypass IP-level rules: degrade to
	 * port-less matching instead of skipping rule evaluation. */
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcph = l4;
		if ((void *)(tcph + 1) <= data_end) {
			sport = tcph->source;
			dport = tcph->dest;
			has_l4 = 1;
		}
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *udph = l4;
		if ((void *)(udph + 1) <= data_end) {
			sport = udph->source;
			dport = udph->dest;
			has_l4 = 1;
		}
	}

	__u32 zero = 0;
	struct pkt_view *dbg = bpf_map_lookup_elem(&debug_last, &zero);
	if (dbg) {
		dbg->saddr = saddr;
		dbg->daddr = daddr;
		dbg->sport = sport;
		dbg->dport = dport;
		dbg->proto = proto;
	}

	/* 1. CIDR blocklist: longest-prefix match on source address. */
	struct lpm_v4_key lpm_key = {
		.prefixlen = 32,
		.addr = saddr,
	};
	__u32 *block_id = bpf_map_lookup_elem(&blocklist, &lpm_key);
	if (block_id) {
		if (st) {
			st->dropped_pkts++;
			st->dropped_bytes += pkt_len;
			st->drop_blocklist++;
		}
		emit_event(saddr, daddr, sport, dport, proto,
			   REASON_DROP_BLOCKLIST, *block_id);
		return XDP_DROP;
	}

	/* 2. protocol/destination-port rules. */
	if (has_l4) {
		struct port_rule_key pk = {
			.proto = proto,
			.pad = 0,
			.dport = dport,
		};
		struct port_rule_val *pv = bpf_map_lookup_elem(&port_rules, &pk);
		if (pv && pv->action == ACTION_DROP) {
			if (st) {
				st->dropped_pkts++;
				st->dropped_bytes += pkt_len;
				st->drop_port++;
			}
			emit_event(saddr, daddr, sport, dport, proto,
				   REASON_DROP_PORT, pv->rule_id);
			return XDP_DROP;
		}
	}

	/* 3. per-source token-bucket rate limit (config matched by LPM). */
	struct rate_cfg *rc = bpf_map_lookup_elem(&rate_cfgs, &lpm_key);
	if (rc && rate_limit_exceeded(saddr, rc)) {
		if (st) {
			st->dropped_pkts++;
			st->dropped_bytes += pkt_len;
			st->drop_ratelimit++;
		}
		emit_event(saddr, daddr, sport, dport, proto,
			   REASON_DROP_RATELIMIT, rc->rule_id);
		return XDP_DROP;
	}

pass:
	if (st)
		st->passed++;
	return XDP_PASS;
}
