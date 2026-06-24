//go:build linux

// Data-plane unit tests via BPF_PROG_TEST_RUN: the kernel executes the
// real XDP program against crafted packets — no NIC, no traffic generator,
// runs in CI. Requires root and bpf/bastion.bpf.o (make bpf).
package prog_test

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const (
	XDP_ABORTED = 0
	XDP_DROP    = 1
	XDP_PASS    = 2
)

const objPath = "../../bpf/bastion.bpf.o"

type lpmKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

type portKey struct {
	Proto uint8
	_     uint8
	Port  [2]byte
}

type portVal struct {
	Action uint32
	RuleID uint32
}

type pktView struct {
	Saddr [4]byte
	Daddr [4]byte
	Sport [2]byte
	Dport [2]byte
	Proto uint8
	_     [3]byte
}

func loadCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (BPF syscalls)")
	}
	if _, err := os.Stat(objPath); err != nil {
		t.Skipf("BPF object not built (%v); run `make bpf` first", err)
	}
	coll, err := ebpf.LoadCollection(objPath)
	if err != nil {
		t.Fatalf("loading collection: %v", err)
	}
	t.Cleanup(coll.Close)
	return coll
}

func run(t *testing.T, coll *ebpf.Collection, pkt []byte) uint32 {
	t.Helper()
	ret, err := coll.Programs["bastion_xdp"].Run(&ebpf.RunOptions{
		Data:   pkt,
		Repeat: 1,
	})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return ret
}

// tcpPacket builds eth/ipv4/tcp with the given source IP and dest port.
func tcpPacket(t *testing.T, src string, dport uint16) []byte {
	t.Helper()
	return l4Packet(t, src, dport, layers.IPProtocolTCP)
}

func l4Packet(t *testing.T, src string, dport uint16, proto layers.IPProtocol) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: proto,
		SrcIP:    net.ParseIP(src),
		DstIP:    net.ParseIP("10.11.0.1"),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	var err error
	switch proto {
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{SrcPort: 40000, DstPort: layers.TCPPort(dport), SYN: true}
		tcp.SetNetworkLayerForChecksum(ip)
		err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("xx")))
	case layers.IPProtocolUDP:
		udp := &layers.UDP{SrcPort: 40000, DstPort: layers.UDPPort(dport)}
		udp.SetNetworkLayerForChecksum(ip)
		err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("xx")))
	default:
		err = gopacket.SerializeLayers(buf, opts, eth, ip, gopacket.Payload([]byte("xx")))
	}
	if err != nil {
		t.Fatalf("building packet: %v", err)
	}
	return buf.Bytes()
}

// Phase 1: clean IPv4/TCP passes and the parser extracted the right tuple.
func TestPassThroughParsesFields(t *testing.T) {
	coll := loadCollection(t)
	pkt := tcpPacket(t, "10.11.0.2", 8080)

	if ret := run(t, coll, pkt); ret != XDP_PASS {
		t.Fatalf("verdict = %d, want XDP_PASS", ret)
	}

	var views []pktView
	key := uint32(0)
	if err := coll.Maps["debug_last"].Lookup(&key, &views); err != nil {
		t.Fatalf("reading debug_last: %v", err)
	}
	// prog_test runs on one CPU; find the populated slot.
	var v pktView
	for _, pv := range views {
		if pv.Proto != 0 {
			v = pv
			break
		}
	}
	if got := net.IP(v.Saddr[:]).String(); got != "10.11.0.2" {
		t.Errorf("parsed saddr = %s, want 10.11.0.2", got)
	}
	if got := uint16(v.Dport[0])<<8 | uint16(v.Dport[1]); got != 8080 {
		t.Errorf("parsed dport = %d, want 8080", got)
	}
	if v.Proto != 6 {
		t.Errorf("parsed proto = %d, want 6 (tcp)", v.Proto)
	}
}

// Phase 2: blocklisted /32 drops, others pass, /24 prefix matches range.
func TestBlocklistLPM(t *testing.T) {
	coll := loadCollection(t)
	bl := coll.Maps["blocklist"]

	add := func(prefixLen uint32, ip string, id uint32) {
		k := lpmKey{PrefixLen: prefixLen}
		copy(k.Addr[:], net.ParseIP(ip).To4())
		if err := bl.Update(&k, &id, ebpf.UpdateAny); err != nil {
			t.Fatalf("blocklist update: %v", err)
		}
	}
	add(32, "10.0.0.5", 1)

	if ret := run(t, coll, tcpPacket(t, "10.0.0.5", 80)); ret != XDP_DROP {
		t.Errorf("blocked /32 source: verdict = %d, want XDP_DROP", ret)
	}
	if ret := run(t, coll, tcpPacket(t, "10.0.0.6", 80)); ret != XDP_PASS {
		t.Errorf("unblocked source: verdict = %d, want XDP_PASS", ret)
	}

	add(24, "192.168.7.0", 2)
	if ret := run(t, coll, tcpPacket(t, "192.168.7.200", 80)); ret != XDP_DROP {
		t.Errorf("source inside blocked /24: verdict = %d, want XDP_DROP", ret)
	}
	if ret := run(t, coll, tcpPacket(t, "192.168.8.1", 80)); ret != XDP_PASS {
		t.Errorf("source outside blocked /24: verdict = %d, want XDP_PASS", ret)
	}
}

// Phase 3: tcp/2222 drops while tcp/22 passes; udp on same port unaffected.
func TestPortRules(t *testing.T) {
	coll := loadCollection(t)

	k := portKey{Proto: 6, Port: [2]byte{2222 >> 8, 2222 & 0xff}}
	v := portVal{Action: 1, RuleID: 42}
	if err := coll.Maps["port_rules"].Update(&k, &v, ebpf.UpdateAny); err != nil {
		t.Fatalf("port_rules update: %v", err)
	}

	if ret := run(t, coll, tcpPacket(t, "10.11.0.2", 2222)); ret != XDP_DROP {
		t.Errorf("tcp/2222: verdict = %d, want XDP_DROP", ret)
	}
	if ret := run(t, coll, tcpPacket(t, "10.11.0.2", 22)); ret != XDP_PASS {
		t.Errorf("tcp/22: verdict = %d, want XDP_PASS", ret)
	}
	if ret := run(t, coll, l4Packet(t, "10.11.0.2", 2222, layers.IPProtocolUDP)); ret != XDP_PASS {
		t.Errorf("udp/2222 (no udp rule): verdict = %d, want XDP_PASS", ret)
	}
}

// Phase 3: stats counters reflect every test-run invocation.
func TestStatsCounters(t *testing.T) {
	coll := loadCollection(t)

	const n = 100
	pkt := tcpPacket(t, "10.11.0.2", 80)
	for i := 0; i < n; i++ {
		if ret := run(t, coll, pkt); ret != XDP_PASS {
			t.Fatalf("verdict = %d, want XDP_PASS", ret)
		}
	}

	type statsRec struct {
		TotalPkts, TotalBytes, DroppedPkts, DroppedBytes uint64
		Passed, DropBlocklist, DropPort, DropRatelimit   uint64
		Aborted, EventDrops                              uint64
	}
	var per []statsRec
	key := uint32(0)
	if err := coll.Maps["stats_map"].Lookup(&key, &per); err != nil {
		t.Fatalf("reading stats: %v", err)
	}
	var total, passed uint64
	for _, s := range per {
		total += s.TotalPkts
		passed += s.Passed
	}
	if total != n || passed != n {
		t.Errorf("stats: total=%d passed=%d, want both %d", total, passed, n)
	}
}

// Section 7: malformed packets must pass (fail open), never crash or
// read out of bounds. The verifier proves safety; these prove behavior.
func TestMalformedPackets(t *testing.T) {
	coll := loadCollection(t)

	full := tcpPacket(t, "10.0.0.5", 80)
	// Blocklist the source: even a blocklisted IP in a truncated packet
	// must PASS because the parse fails before any lookup applies.
	k := lpmKey{PrefixLen: 32}
	copy(k.Addr[:], net.ParseIP("10.0.0.5").To4())
	id := uint32(9)
	if err := coll.Maps["blocklist"].Update(&k, &id, ebpf.UpdateAny); err != nil {
		t.Fatalf("blocklist update: %v", err)
	}

	clean := tcpPacket(t, "10.11.0.2", 80)

	cases := []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"truncated ethernet+", full[:16], XDP_PASS},
		{"truncated ip header", full[:20], XDP_PASS},
		// L4 truncation degrades to port-less matching: the blocklist
		// (IP-level) still applies, a clean source still passes.
		{"truncated tcp, blocked source", full[:38], XDP_DROP},
		{"truncated tcp, clean source", clean[:38], XDP_PASS},
		{"non-ip ethertype", func() []byte {
			p := append([]byte(nil), full...)
			p[12], p[13] = 0x08, 0x06 // ARP
			return p
		}(), XDP_PASS},
		{"bad ihl", func() []byte {
			p := append([]byte(nil), full...)
			p[14] = 0x42 // version 4, ihl 2 (< 5): malformed
			return p
		}(), XDP_PASS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if ret := run(t, coll, tc.pkt); ret != tc.want {
				t.Errorf("verdict = %d, want %d", ret, tc.want)
			}
		})
	}
}

// Phase 4: token bucket passes the burst then drops until refill.
func TestRateLimiter(t *testing.T) {
	coll := loadCollection(t)

	type rateCfg struct {
		PPS    uint64
		Burst  uint64
		RuleID uint32
		_      uint32
	}
	k := lpmKey{PrefixLen: 32}
	copy(k.Addr[:], net.ParseIP("10.9.9.9").To4())
	// 1 pps with burst 10: in a tight loop, ~10 packets pass, the rest drop.
	cfg := rateCfg{PPS: 1, Burst: 10, RuleID: 7}
	if err := coll.Maps["rate_cfgs"].Update(&k, &cfg, ebpf.UpdateAny); err != nil {
		t.Fatalf("rate_cfgs update: %v", err)
	}

	pkt := tcpPacket(t, "10.9.9.9", 80)
	var passed, dropped int
	for i := 0; i < 50; i++ {
		switch run(t, coll, pkt) {
		case XDP_PASS:
			passed++
		case XDP_DROP:
			dropped++
		}
	}
	// Allow +1 for a refill during the loop.
	if passed < 10 || passed > 12 {
		t.Errorf("passed = %d, want ~burst (10)", passed)
	}
	if dropped < 38 {
		t.Errorf("dropped = %d, want >= 38", dropped)
	}
}
