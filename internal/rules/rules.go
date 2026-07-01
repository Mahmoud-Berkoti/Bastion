// Package rules owns policy: it compiles the declarative config into BPF
// map entries and reconciles the maps whenever the desired state changes
// (file reload or API mutation). The kernel never sees policy logic, only
// map contents.
package rules

import (
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"gopkg.in/yaml.v3"
)

// Manager is the interface both the real (BPF-backed) and fake (demo)
// managers satisfy, so api.Server is independent of the backend.
type Manager interface {
	Snapshot() Config
	RuleName(id uint32) string
	AddBlocklist(cidr string) error
	RemoveBlocklist(cidr string) error
	AddPortRule(pr PortRule) error
	RemovePortRule(proto string, port uint16) error
	AddRateLimit(rl RateLimit) error
	RemoveRateLimit(cidr string) error
}

type PortRule struct {
	Proto  string `yaml:"proto" json:"proto"`   // "tcp" | "udp"
	Port   uint16 `yaml:"port" json:"port"`     // destination port
	Action string `yaml:"action" json:"action"` // "drop" | "pass"
}

type RateLimit struct {
	CIDR  string `yaml:"cidr" json:"cidr"`
	PPS   uint64 `yaml:"pps" json:"pps"`
	Burst uint64 `yaml:"burst" json:"burst"`
}

type Config struct {
	Blocklist  []string    `yaml:"blocklist" json:"blocklist"`
	PortRules  []PortRule  `yaml:"port_rules" json:"port_rules"`
	RateLimits []RateLimit `yaml:"rate_limits" json:"rate_limits"`
}

// Map value/key layouts mirroring bpf/common.h. Field order and padding
// must match exactly; cilium/ebpf marshals these with native endianness,
// so network-order fields are kept as byte arrays.
type lpmKey struct {
	PrefixLen uint32
	Addr      [4]byte // network byte order
}

type portKey struct {
	Proto uint8
	_     uint8
	Port  [2]byte // network byte order
}

type portVal struct {
	Action uint32
	RuleID uint32
}

type rateCfgVal struct {
	PPS    uint64
	Burst  uint64
	RuleID uint32
	_      uint32
}

const (
	actionPass uint32 = 0
	actionDrop uint32 = 1
)

// Manager reconciles desired config into the BPF maps. It also keeps a
// rule-id registry so events can be resolved back to human-readable rules.
// BPFManager is the real, kernel-backed rule manager used in production.
type BPFManager struct {
	mu        sync.Mutex
	blocklist *ebpf.Map
	portRules *ebpf.Map
	rateCfgs  *ebpf.Map

	current  Config
	registry map[uint32]string // rule id -> description
}

func NewBPFManager(blocklist, portRules, rateCfgs *ebpf.Map) *BPFManager {
	return &BPFManager{
		blocklist: blocklist,
		portRules: portRules,
		rateCfgs:  rateCfgs,
		registry:  map[uint32]string{},
	}
}

func LoadFile(path string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	for _, cidr := range c.Blocklist {
		if _, err := parseCIDR(cidr); err != nil {
			return fmt.Errorf("blocklist entry %q: %w", cidr, err)
		}
	}
	for _, pr := range c.PortRules {
		if _, err := protoNum(pr.Proto); err != nil {
			return err
		}
		if pr.Action != "drop" && pr.Action != "pass" {
			return fmt.Errorf("port rule %s/%d: action must be drop or pass", pr.Proto, pr.Port)
		}
		if pr.Port == 0 {
			return fmt.Errorf("port rule %s: port must be 1-65535", pr.Proto)
		}
	}
	for _, rl := range c.RateLimits {
		if _, err := parseCIDR(rl.CIDR); err != nil {
			return fmt.Errorf("rate limit %q: %w", rl.CIDR, err)
		}
		if rl.PPS == 0 {
			return fmt.Errorf("rate limit %s: pps must be > 0", rl.CIDR)
		}
	}
	return nil
}

// Reconcile makes the BPF maps match cfg: adds missing entries, removes
// stale ones, updates changed values. It never touches the program itself,
// so rule changes are zero-reload.
func (m *BPFManager)Reconcile(cfg Config) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	registry := map[uint32]string{}

	// Blocklist (LPM trie)
	desiredBlock := map[lpmKey]uint32{}
	for _, cidr := range cfg.Blocklist {
		k, _ := parseCIDR(cidr)
		desc := "blocklist:" + canonCIDR(cidr)
		id := ruleID(desc)
		desiredBlock[k] = id
		registry[id] = desc
	}
	if err := reconcileMap(m.blocklist, desiredBlock); err != nil {
		return fmt.Errorf("blocklist: %w", err)
	}

	// Port rules (hash)
	desiredPorts := map[portKey]portVal{}
	for _, pr := range cfg.PortRules {
		proto, _ := protoNum(pr.Proto)
		desc := fmt.Sprintf("port:%s/%d:%s", strings.ToLower(pr.Proto), pr.Port, pr.Action)
		id := ruleID(desc)
		action := actionPass
		if pr.Action == "drop" {
			action = actionDrop
		}
		k := portKey{Proto: proto}
		k.Port[0] = byte(pr.Port >> 8) // network byte order
		k.Port[1] = byte(pr.Port)
		desiredPorts[k] = portVal{Action: action, RuleID: id}
		registry[id] = desc
	}
	if err := reconcileMap(m.portRules, desiredPorts); err != nil {
		return fmt.Errorf("port rules: %w", err)
	}

	// Rate limits (LPM trie)
	desiredRates := map[lpmKey]rateCfgVal{}
	for _, rl := range cfg.RateLimits {
		k, _ := parseCIDR(rl.CIDR)
		desc := fmt.Sprintf("ratelimit:%s:%dpps", canonCIDR(rl.CIDR), rl.PPS)
		id := ruleID(desc)
		desiredRates[k] = rateCfgVal{PPS: rl.PPS, Burst: rl.Burst, RuleID: id}
		registry[id] = desc
	}
	if err := reconcileMap(m.rateCfgs, desiredRates); err != nil {
		return fmt.Errorf("rate limits: %w", err)
	}

	m.current = cfg
	m.registry = registry
	return nil
}

// Snapshot returns the currently applied config.
func (m *BPFManager)Snapshot() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// RuleName resolves a rule id from an event to its description.
func (m *BPFManager)RuleName(id uint32) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.registry[id]; ok {
		return d
	}
	return ""
}

// AddBlocklist / RemoveBlocklist etc. mutate the current config and
// reconcile, so API changes and file reloads go through one code path.

func (m *BPFManager)AddBlocklist(cidr string) error {
	cfg := m.Snapshot()
	c := canonCIDR(cidr)
	for _, existing := range cfg.Blocklist {
		if canonCIDR(existing) == c {
			return nil
		}
	}
	cfg.Blocklist = append(cfg.Blocklist, cidr)
	return m.Reconcile(cfg)
}

func (m *BPFManager)RemoveBlocklist(cidr string) error {
	cfg := m.Snapshot()
	c := canonCIDR(cidr)
	out := cfg.Blocklist[:0]
	for _, existing := range cfg.Blocklist {
		if canonCIDR(existing) != c {
			out = append(out, existing)
		}
	}
	cfg.Blocklist = out
	return m.Reconcile(cfg)
}

func (m *BPFManager)AddPortRule(pr PortRule) error {
	cfg := m.Snapshot()
	for i, existing := range cfg.PortRules {
		if strings.EqualFold(existing.Proto, pr.Proto) && existing.Port == pr.Port {
			cfg.PortRules[i] = pr
			return m.Reconcile(cfg)
		}
	}
	cfg.PortRules = append(cfg.PortRules, pr)
	return m.Reconcile(cfg)
}

func (m *BPFManager)RemovePortRule(proto string, port uint16) error {
	cfg := m.Snapshot()
	out := cfg.PortRules[:0]
	for _, existing := range cfg.PortRules {
		if !(strings.EqualFold(existing.Proto, proto) && existing.Port == port) {
			out = append(out, existing)
		}
	}
	cfg.PortRules = out
	return m.Reconcile(cfg)
}

func (m *BPFManager)AddRateLimit(rl RateLimit) error {
	cfg := m.Snapshot()
	c := canonCIDR(rl.CIDR)
	for i, existing := range cfg.RateLimits {
		if canonCIDR(existing.CIDR) == c {
			cfg.RateLimits[i] = rl
			return m.Reconcile(cfg)
		}
	}
	cfg.RateLimits = append(cfg.RateLimits, rl)
	return m.Reconcile(cfg)
}

func (m *BPFManager)RemoveRateLimit(cidr string) error {
	cfg := m.Snapshot()
	c := canonCIDR(cidr)
	out := cfg.RateLimits[:0]
	for _, existing := range cfg.RateLimits {
		if canonCIDR(existing.CIDR) != c {
			out = append(out, existing)
		}
	}
	cfg.RateLimits = out
	return m.Reconcile(cfg)
}

// reconcileMap diffs desired against the live map: update everything
// desired (BPF_ANY is idempotent), delete anything no longer wanted.
func reconcileMap[K comparable, V any](m *ebpf.Map, desired map[K]V) error {
	for k, v := range desired {
		k, v := k, v
		if err := m.Update(&k, &v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update: %w", err)
		}
	}
	var stale []K
	var k K
	var v V
	it := m.Iterate()
	for it.Next(&k, &v) {
		if _, ok := desired[k]; !ok {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate: %w", err)
	}
	for _, k := range stale {
		k := k
		if err := m.Delete(&k); err != nil {
			return fmt.Errorf("delete: %w", err)
		}
	}
	return nil
}

func parseCIDR(s string) (lpmKey, error) {
	// Accept bare IPs as /32.
	if !strings.Contains(s, "/") {
		s += "/32"
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return lpmKey{}, err
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return lpmKey{}, fmt.Errorf("%s: only IPv4 is supported", s)
	}
	ones, _ := ipnet.Mask.Size()
	var k lpmKey
	k.PrefixLen = uint32(ones)
	copy(k.Addr[:], ip4)
	return k, nil
}

func canonCIDR(s string) string {
	if !strings.Contains(s, "/") {
		s += "/32"
	}
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return ipnet.String()
	}
	return s
}

func protoNum(p string) (uint8, error) {
	switch strings.ToLower(p) {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q (tcp|udp)", p)
	}
}

func ruleID(desc string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(desc))
	return h.Sum32()
}
