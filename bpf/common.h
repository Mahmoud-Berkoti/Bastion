/* SPDX-License-Identifier: GPL-2.0 */
/* Structs shared between the XDP data plane and (by layout) the Go control
 * plane. Include after vmlinux.h — the __uNN types come from there. */
#ifndef __BASTION_COMMON_H
#define __BASTION_COMMON_H

/* Why a packet was dropped (or passed). Carried in events and stats. */
enum bastion_reason {
	REASON_PASS           = 0,
	REASON_DROP_BLOCKLIST = 1,
	REASON_DROP_PORT      = 2,
	REASON_DROP_RATELIMIT = 3,
};

enum bastion_action {
	ACTION_PASS = 0,
	ACTION_DROP = 1,
};

/* LPM trie key: prefixlen in bits, address in network byte order.
 * Used for both the blocklist and the rate-limit config trie. */
struct lpm_v4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct port_rule_key {
	__u8  proto;  /* IPPROTO_TCP / IPPROTO_UDP */
	__u8  pad;
	__u16 dport;  /* network byte order */
};

struct port_rule_val {
	__u32 action; /* enum bastion_action */
	__u32 rule_id;
};

struct rate_cfg {
	__u64 rate_pps; /* sustained tokens per second */
	__u64 burst;    /* bucket depth in tokens */
	__u32 rule_id;
	__u32 pad;
};

struct token_bucket {
	__u64 tokens;  /* fixed point, scaled by TOKEN_SCALE */
	__u64 last_ns; /* bpf_ktime_get_ns() of last refill */
};

/* One entry in a per-CPU array; userspace sums across CPUs. */
struct stats {
	__u64 total_pkts;
	__u64 total_bytes;
	__u64 dropped_pkts;
	__u64 dropped_bytes;
	__u64 passed;
	__u64 drop_blocklist;
	__u64 drop_port;
	__u64 drop_ratelimit;
	__u64 aborted;
	__u64 event_drops; /* ring buffer reserve failures */
};

/* Ring buffer event record. Keep in sync with internal/events. */
struct event {
	__u64 ts_ns;
	__u32 saddr;   /* network byte order */
	__u32 daddr;
	__u16 sport;   /* network byte order */
	__u16 dport;
	__u8  proto;
	__u8  reason;  /* enum bastion_reason */
	__u16 pad;
	__u32 rule_id;
	__u32 pad2;
};

/* Last successfully parsed tuple; only read by BPF_PROG_TEST_RUN tests. */
struct pkt_view {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  proto;
	__u8  pad[3];
};

#endif /* __BASTION_COMMON_H */
