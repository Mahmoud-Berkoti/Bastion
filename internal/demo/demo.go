// Package demo provides a self-contained fake back-end for running the
// dashboard on macOS / non-Linux hosts where BPF syscalls are unavailable.
// It generates realistic synthetic stats and events so the UI is fully
// exercisable without a real kernel or NIC.
package demo

import (
	"math/rand"
	"sync"
	"time"

	"github.com/mberkoti/bastion/internal/events"
	"github.com/mberkoti/bastion/internal/rules"
	"github.com/mberkoti/bastion/internal/stats"
)

// FakeStats implements a stats.Reader backed by synthetic counters that
// grow at realistic rates.
type FakeStats struct {
	mu      sync.Mutex
	total   uint64
	bytes   uint64
	dropped uint64
	dbytes  uint64
	passed  uint64
	block   uint64
	port    uint64
	rate    uint64
}

func (f *FakeStats) Tick() {
	f.mu.Lock()
	defer f.mu.Unlock()
	pps := uint64(80_000 + rand.Intn(40_000))
	drop := uint64(float64(pps) * (0.03 + rand.Float64()*0.05))
	bps := pps * uint64(64+rand.Intn(512))

	f.total += pps
	f.bytes += bps
	f.dropped += drop
	f.dbytes += drop * 64
	f.passed += pps - drop

	bl := drop * uint64(40+rand.Intn(30)) / 100
	prt := drop * uint64(20+rand.Intn(20)) / 100
	f.block += bl
	f.port += prt
	f.rate += drop - bl - prt
}

func (f *FakeStats) Read() (stats.Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return stats.Stats{
		TotalPackets:   f.total,
		TotalBytes:     f.bytes,
		DroppedPackets: f.dropped,
		DroppedBytes:   f.dbytes,
		Passed:         f.passed,
		DropBlocklist:  f.block,
		DropPort:       f.port,
		DropRatelimit:  f.rate,
	}, nil
}

// FakeReader wraps FakeStats to satisfy the interface expected by api.Server.
type FakeReader struct{ *FakeStats }

// NewFakeReader creates a fake stats source and starts its tick goroutine.
func NewFakeReader() *FakeReader {
	fs := &FakeStats{}
	// Seed with some history so counters aren't zero on first load.
	for range 120 {
		fs.Tick()
	}
	go func() {
		t := time.NewTicker(time.Second)
		for range t.C {
			fs.Tick()
		}
	}()
	return &FakeReader{fs}
}

// Read satisfies stats.Reader.
func (r *FakeReader) Read() (stats.Stats, error) { return r.FakeStats.Read() }

var sources = []string{
	"10.11.0.66", "192.0.2.44", "172.16.5.11",
	"10.0.0.5", "198.51.100.7", "203.0.113.2",
}

var reasons = []struct {
	key  string
	rule string
}{
	{"drop_blocklist", "blocklist:192.0.2.0/24"},
	{"drop_port", "port:tcp/2222:drop"},
	{"drop_ratelimit", "ratelimit:10.11.0.0/24:1000pps"},
}

var protos = []string{"tcp", "udp", "icmp"}
var dstPorts = []uint16{80, 443, 22, 2222, 8080, 53}

// StartFakeEvents pumps synthetic events into hub at a moderate rate.
func StartFakeEvents(hub *events.Hub) {
	go func() {
		t := time.NewTicker(600 * time.Millisecond)
		for range t.C {
			if rand.Intn(3) == 0 {
				continue // occasional quiet tick
			}
			r := reasons[rand.Intn(len(reasons))]
			hub.InjectFake(events.Event{
				Time:     time.Now(),
				Src:      sources[rand.Intn(len(sources))],
				Dst:      "10.11.0.1",
				SrcPort:  uint16(30000 + rand.Intn(30000)),
				DstPort:  dstPorts[rand.Intn(len(dstPorts))],
				Proto:    protos[rand.Intn(len(protos))],
				Reason:   r.key,
				RuleName: r.rule,
			})
		}
	}()
}

// DemoRules returns a starter config suitable for showing off the dashboard.
func DemoRules() rules.Config {
	return rules.Config{
		Blocklist: []string{"192.0.2.0/24", "10.11.0.66/32"},
		PortRules: []rules.PortRule{
			{Proto: "tcp", Port: 2222, Action: "drop"},
		},
		RateLimits: []rules.RateLimit{
			{CIDR: "10.11.0.0/24", PPS: 1000, Burst: 200},
		},
	}
}
