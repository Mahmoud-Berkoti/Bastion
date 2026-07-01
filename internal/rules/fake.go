package rules

import "sync"

// FakeManager satisfies the same surface as Manager but stores rules in
// memory, with no BPF maps. Used by the demo mode on non-Linux hosts.
type FakeManager struct {
	mu       sync.Mutex
	current  Config
	registry map[uint32]string
}

func NewFakeManager() *FakeManager {
	return &FakeManager{registry: map[uint32]string{}}
}

func (m *FakeManager) ReconcileConfig(cfg Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = cfg
	m.registry = map[uint32]string{}
	for _, cidr := range cfg.Blocklist {
		desc := "blocklist:" + canonCIDR(cidr)
		m.registry[ruleID(desc)] = desc
	}
	for _, pr := range cfg.PortRules {
		desc := "port:" + pr.Proto + "/" + itoa(int(pr.Port)) + ":" + pr.Action
		m.registry[ruleID(desc)] = desc
	}
	for _, rl := range cfg.RateLimits {
		desc := "ratelimit:" + canonCIDR(rl.CIDR) + ":" + itoa(int(rl.PPS)) + "pps"
		m.registry[ruleID(desc)] = desc
	}
}

func (m *FakeManager) Reconcile(cfg Config) error {
	m.ReconcileConfig(cfg)
	return nil
}

func (m *FakeManager) Snapshot() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

func (m *FakeManager) RuleName(id uint32) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.registry[id]
}

func (m *FakeManager) AddBlocklist(cidr string) error {
	cfg := m.Snapshot()
	c := canonCIDR(cidr)
	for _, e := range cfg.Blocklist {
		if canonCIDR(e) == c {
			return nil
		}
	}
	cfg.Blocklist = append(cfg.Blocklist, cidr)
	m.ReconcileConfig(cfg)
	return nil
}

func (m *FakeManager) RemoveBlocklist(cidr string) error {
	cfg := m.Snapshot()
	c := canonCIDR(cidr)
	out := cfg.Blocklist[:0]
	for _, e := range cfg.Blocklist {
		if canonCIDR(e) != c {
			out = append(out, e)
		}
	}
	cfg.Blocklist = out
	m.ReconcileConfig(cfg)
	return nil
}

func (m *FakeManager) AddPortRule(pr PortRule) error {
	cfg := m.Snapshot()
	for i, e := range cfg.PortRules {
		if strEq(e.Proto, pr.Proto) && e.Port == pr.Port {
			cfg.PortRules[i] = pr
			m.ReconcileConfig(cfg)
			return nil
		}
	}
	cfg.PortRules = append(cfg.PortRules, pr)
	m.ReconcileConfig(cfg)
	return nil
}

func (m *FakeManager) RemovePortRule(proto string, port uint16) error {
	cfg := m.Snapshot()
	out := cfg.PortRules[:0]
	for _, e := range cfg.PortRules {
		if !(strEq(e.Proto, proto) && e.Port == port) {
			out = append(out, e)
		}
	}
	cfg.PortRules = out
	m.ReconcileConfig(cfg)
	return nil
}

func (m *FakeManager) AddRateLimit(rl RateLimit) error {
	cfg := m.Snapshot()
	c := canonCIDR(rl.CIDR)
	for i, e := range cfg.RateLimits {
		if canonCIDR(e.CIDR) == c {
			cfg.RateLimits[i] = rl
			m.ReconcileConfig(cfg)
			return nil
		}
	}
	cfg.RateLimits = append(cfg.RateLimits, rl)
	m.ReconcileConfig(cfg)
	return nil
}

func (m *FakeManager) RemoveRateLimit(cidr string) error {
	cfg := m.Snapshot()
	c := canonCIDR(cidr)
	out := cfg.RateLimits[:0]
	for _, e := range cfg.RateLimits {
		if canonCIDR(e.CIDR) != c {
			out = append(out, e)
		}
	}
	cfg.RateLimits = out
	m.ReconcileConfig(cfg)
	return nil
}

func strEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
