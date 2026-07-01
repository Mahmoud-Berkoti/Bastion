// Package stats aggregates the per-CPU stats map into a single view.
// The data plane increments per-CPU slots without atomics; correctness
// comes from summing here, in userspace, off the hot path.
package stats

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Stats mirrors struct stats in bpf/common.h.
type Stats struct {
	TotalPackets   uint64 `json:"total_packets"`
	TotalBytes     uint64 `json:"total_bytes"`
	DroppedPackets uint64 `json:"dropped_packets"`
	DroppedBytes   uint64 `json:"dropped_bytes"`
	Passed         uint64 `json:"passed"`
	DropBlocklist  uint64 `json:"drop_blocklist"`
	DropPort       uint64 `json:"drop_port"`
	DropRatelimit  uint64 `json:"drop_ratelimit"`
	Aborted        uint64 `json:"aborted"`
	EventDrops     uint64 `json:"event_drops"`
}

// Source is anything that can return a Stats snapshot.
type Source interface {
	Read() (Stats, error)
}

type Reader struct {
	m *ebpf.Map
}

func NewReader(m *ebpf.Map) *Reader {
	return &Reader{m: m}
}

// Read sums the single stats entry across all CPUs.
func (r *Reader) Read() (Stats, error) {
	var perCPU []Stats
	key := uint32(0)
	if err := r.m.Lookup(&key, &perCPU); err != nil {
		return Stats{}, fmt.Errorf("reading stats map: %w", err)
	}
	var out Stats
	for _, s := range perCPU {
		out.TotalPackets += s.TotalPackets
		out.TotalBytes += s.TotalBytes
		out.DroppedPackets += s.DroppedPackets
		out.DroppedBytes += s.DroppedBytes
		out.Passed += s.Passed
		out.DropBlocklist += s.DropBlocklist
		out.DropPort += s.DropPort
		out.DropRatelimit += s.DropRatelimit
		out.Aborted += s.Aborted
		out.EventDrops += s.EventDrops
	}
	return out, nil
}
