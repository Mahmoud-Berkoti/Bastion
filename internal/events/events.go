// Package events consumes the BPF ring buffer and fans events out to the
// API: a bounded in-memory history for GET /events and live channels for
// the SSE stream. The kernel already samples under load, so this side just
// has to keep up with the (bounded) event rate.
package events

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// Reasons mirror enum bastion_reason in bpf/common.h.
var reasonNames = map[uint8]string{
	0: "pass",
	1: "drop_blocklist",
	2: "drop_port",
	3: "drop_ratelimit",
}

var protoNames = map[uint8]string{
	1:  "icmp",
	6:  "tcp",
	17: "udp",
}

type Event struct {
	Time     time.Time `json:"time"`
	Src      string    `json:"src"`
	Dst      string    `json:"dst"`
	SrcPort  uint16    `json:"src_port"`
	DstPort  uint16    `json:"dst_port"`
	Proto    string    `json:"proto"`
	Reason   string    `json:"reason"`
	RuleID   uint32    `json:"rule_id"`
	RuleName string    `json:"rule_name,omitempty"`
}

// RuleResolver turns a rule id into a human-readable name (rules.Manager).
type RuleResolver interface {
	RuleName(id uint32) string
}

type Hub struct {
	resolve RuleResolver

	mu   sync.Mutex
	buf  []Event // ring, newest at end
	max  int
	subs map[chan Event]struct{}
}

func NewHub(historySize int, resolve RuleResolver) *Hub {
	return &Hub{
		resolve: resolve,
		max:     historySize,
		subs:    map[chan Event]struct{}{},
	}
}

// Run blocks reading the ring buffer until ctx is cancelled.
func (h *Hub) Run(ctx context.Context, ringMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(ringMap)
	if err != nil {
		return fmt.Errorf("opening ring buffer: %w", err)
	}
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("ring buffer read: %v", err)
			continue
		}
		ev, err := decode(rec.RawSample)
		if err != nil {
			log.Printf("ring buffer decode: %v", err)
			continue
		}
		if h.resolve != nil {
			ev.RuleName = h.resolve.RuleName(ev.RuleID)
		}
		h.publish(ev)
	}
}

// decode parses struct event from bpf/common.h (little-endian scalars,
// addresses and ports already in network byte order).
func decode(raw []byte) (Event, error) {
	if len(raw) < 28 {
		return Event{}, fmt.Errorf("short event record: %d bytes", len(raw))
	}
	return Event{
		// ts_ns is CLOCK_MONOTONIC (since boot); wall-clock arrival time
		// is more useful to display and the events are read within ms.
		Time:    time.Now(),
		Src:     net.IP(raw[8:12]).String(),
		Dst:     net.IP(raw[12:16]).String(),
		SrcPort: binary.BigEndian.Uint16(raw[16:18]),
		DstPort: binary.BigEndian.Uint16(raw[18:20]),
		Proto:   nameOr(protoNames, raw[20]),
		Reason:  nameOr(reasonNames, raw[21]),
		RuleID:  binary.LittleEndian.Uint32(raw[24:28]),
	}, nil
}

func nameOr(names map[uint8]string, v uint8) string {
	if n, ok := names[v]; ok {
		return n
	}
	return fmt.Sprintf("unknown(%d)", v)
}

func (h *Hub) publish(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf = append(h.buf, ev)
	if len(h.buf) > h.max {
		h.buf = h.buf[len(h.buf)-h.max:]
	}
	for ch := range h.subs {
		select {
		case ch <- ev:
		default: // slow subscriber: drop rather than block the reader
		}
	}
}

// Recent returns up to limit most recent events, newest first.
func (h *Hub) Recent(limit int) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	if limit <= 0 || limit > len(h.buf) {
		limit = len(h.buf)
	}
	out := make([]Event, limit)
	for i := 0; i < limit; i++ {
		out[i] = h.buf[len(h.buf)-1-i]
	}
	return out
}

// InjectFake injects a synthetic event directly — used by the demo mode.
func (h *Hub) InjectFake(ev Event) { h.publish(ev) }

// Subscribe returns a channel of live events; call the returned cancel
// func to unsubscribe.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}
