// Bastion control plane: loads the XDP data plane, pushes declarative
// rules into BPF maps, and serves the REST API / dashboard / metrics.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/mberkoti/bastion/internal/api"
	"github.com/mberkoti/bastion/internal/events"
	"github.com/mberkoti/bastion/internal/loader"
	"github.com/mberkoti/bastion/internal/metrics"
	"github.com/mberkoti/bastion/internal/rules"
	"github.com/mberkoti/bastion/internal/stats"
)

func main() {
	var (
		iface       = flag.String("iface", "", "network interface to attach XDP to (required)")
		obj         = flag.String("obj", "bpf/bastion.bpf.o", "compiled BPF object")
		cfgPath     = flag.String("config", "config/rules.yaml", "declarative rules file")
		apiAddr     = flag.String("api-addr", ":8080", "REST API + dashboard listen address")
		metricsAddr = flag.String("metrics-addr", ":9090", "Prometheus listen address")
		mode        = flag.String("mode", "auto", "XDP attach mode: native|generic|auto")
		sampleRate  = flag.Uint("event-sample-rate", 1, "emit every Nth drop event (per CPU)")
	)
	flag.Parse()
	if *iface == "" {
		log.Fatal("-iface is required (use a veth for testing, never your only NIC)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	b, err := loader.Load(*obj, *iface, *mode, uint32(*sampleRate))
	if err != nil {
		log.Fatalf("loading data plane: %v", err)
	}
	defer b.Close()

	mgr := rules.NewManager(b.Blocklist, b.PortRules, b.RateCfgs)
	cfg, err := rules.LoadFile(*cfgPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}
	if err := mgr.Reconcile(cfg); err != nil {
		log.Fatalf("applying rules: %v", err)
	}
	log.Printf("applied %d blocklist, %d port, %d rate-limit rules from %s",
		len(cfg.Blocklist), len(cfg.PortRules), len(cfg.RateLimits), *cfgPath)

	hub := events.NewHub(1024, mgr)
	go func() {
		if err := hub.Run(ctx, b.Events); err != nil {
			log.Printf("event reader stopped: %v", err)
		}
	}()

	go watchConfig(ctx, *cfgPath, mgr)

	statsReader := stats.NewReader(b.Stats)

	apiSrv := &http.Server{
		Addr: *apiAddr,
		Handler: (&api.Server{
			Rules:  mgr,
			Stats:  statsReader,
			Events: hub,
			Iface:  *iface,
			Mode:   b.AttachedM,
			ProgID: b.ProgID,
		}).Handler(),
	}
	metricsSrv := &http.Server{Addr: *metricsAddr, Handler: metrics.Handler(statsReader)}

	go serve("api", apiSrv)
	go serve("metrics", metricsSrv)
	log.Printf("dashboard/API on %s, prometheus on %s", *apiAddr, *metricsAddr)

	<-ctx.Done()
	log.Println("shutting down: detaching XDP program")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	apiSrv.Shutdown(shutdownCtx)
	metricsSrv.Shutdown(shutdownCtx)
}

func serve(name string, srv *http.Server) {
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("%s server: %v", name, err)
	}
}

// watchConfig reconciles the maps whenever rules.yaml changes — a small
// declarative controller: desired state in the file, actual state in maps.
func watchConfig(ctx context.Context, path string, mgr *rules.Manager) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("config watch disabled: %v", err)
		return
	}
	defer w.Close()
	// Watch the directory: editors replace files, which drops the watch
	// if you watch the file itself.
	if err := w.Add(filepath.Dir(path)); err != nil {
		log.Printf("config watch disabled: %v", err)
		return
	}
	target := filepath.Clean(path)

	var timer *time.Timer
	reload := func() {
		cfg, err := rules.LoadFile(path)
		if err != nil {
			log.Printf("config reload skipped: %v", err)
			return
		}
		if err := mgr.Reconcile(cfg); err != nil {
			log.Printf("config reconcile failed: %v", err)
			return
		}
		log.Printf("reloaded rules from %s", path)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if filepath.Clean(ev.Name) != target {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			// Debounce editor write bursts.
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(200*time.Millisecond, reload)
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			log.Printf("config watch error: %v", err)
		}
	}
}
