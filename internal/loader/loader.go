// Package loader loads the compiled BPF object, attaches the XDP program
// to an interface, and hands out map handles to the rest of the control
// plane. It owns the program lifecycle: Close() detaches cleanly.
package loader

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Bastion struct {
	coll *ebpf.Collection
	lnk  link.Link

	ProgID    uint32
	AttachedM string // "native" or "generic"

	Blocklist *ebpf.Map
	PortRules *ebpf.Map
	RateCfgs  *ebpf.Map
	RateState *ebpf.Map
	Stats     *ebpf.Map
	Events    *ebpf.Map
}

// Load reads the BPF object from objPath, patches the event sample rate,
// loads it through the verifier, and attaches to ifaceName.
// mode is "native", "generic", or "auto" (native with generic fallback —
// veth pairs support native, but not every driver does).
func Load(objPath, ifaceName, mode string, sampleRate uint32) (*Bastion, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("loading collection spec %s: %w", objPath, err)
	}
	if sampleRate == 0 {
		sampleRate = 1
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"event_sample_rate": sampleRate,
	}); err != nil {
		return nil, fmt.Errorf("patching event_sample_rate: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			// Surface the full verifier log: the fix is always in the
			// program logic, never in loosening bounds checks.
			return nil, fmt.Errorf("verifier rejected program:\n%+v", verr)
		}
		return nil, fmt.Errorf("loading collection: %w", err)
	}

	prog := coll.Programs["bastion_xdp"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("program bastion_xdp not found in %s", objPath)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}

	lnk, attached, err := attach(prog, iface.Index, mode)
	if err != nil {
		coll.Close()
		return nil, err
	}

	info, err := prog.Info()
	var progID uint32
	if err == nil {
		if id, ok := info.ID(); ok {
			progID = uint32(id)
		}
	}

	b := &Bastion{
		coll:      coll,
		lnk:       lnk,
		ProgID:    progID,
		AttachedM: attached,
		Blocklist: coll.Maps["blocklist"],
		PortRules: coll.Maps["port_rules"],
		RateCfgs:  coll.Maps["rate_cfgs"],
		RateState: coll.Maps["rate_state"],
		Stats:     coll.Maps["stats_map"],
		Events:    coll.Maps["events"],
	}
	for name, m := range map[string]*ebpf.Map{
		"blocklist": b.Blocklist, "port_rules": b.PortRules,
		"rate_cfgs": b.RateCfgs, "rate_state": b.RateState,
		"stats_map": b.Stats, "events": b.Events,
	} {
		if m == nil {
			b.Close()
			return nil, fmt.Errorf("map %s not found in object", name)
		}
	}
	log.Printf("attached bastion_xdp (prog id %d) to %s in %s mode",
		progID, ifaceName, attached)
	return b, nil
}

func attach(prog *ebpf.Program, ifindex int, mode string) (link.Link, string, error) {
	try := func(flags link.XDPAttachFlags) (link.Link, error) {
		return link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifindex,
			Flags:     flags,
		})
	}
	switch mode {
	case "native":
		l, err := try(link.XDPDriverMode)
		return l, "native", err
	case "generic":
		l, err := try(link.XDPGenericMode)
		return l, "generic", err
	case "auto":
		if l, err := try(link.XDPDriverMode); err == nil {
			return l, "native", nil
		}
		log.Printf("native XDP unavailable on ifindex %d, falling back to generic (SKB) mode", ifindex)
		l, err := try(link.XDPGenericMode)
		return l, "generic", err
	default:
		return nil, "", fmt.Errorf("unknown xdp mode %q (native|generic|auto)", mode)
	}
}

// Close detaches the XDP program and releases all maps.
func (b *Bastion) Close() {
	if b.lnk != nil {
		b.lnk.Close()
	}
	if b.coll != nil {
		b.coll.Close()
	}
}
