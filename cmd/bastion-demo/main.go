// bastion-demo runs the dashboard and REST API backed by synthetic data.
// It works on any platform (macOS, Windows) without a Linux kernel or NIC.
// Useful for demonstrating the UI and the API surface during development.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mberkoti/bastion/internal/api"
	"github.com/mberkoti/bastion/internal/demo"
	"github.com/mberkoti/bastion/internal/events"
	"github.com/mberkoti/bastion/internal/metrics"
	"github.com/mberkoti/bastion/internal/rules"
)

func main() {
	addr := flag.String("addr", ":8080", "dashboard + API listen address")
	maddr := flag.String("metrics-addr", ":9090", "Prometheus listen address")
	flag.Parse()

	log.SetFlags(log.Ltime)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Fake stats source — ticks in the background, no kernel required.
	statsReader := demo.NewFakeReader()

	// Rules manager backed by an in-memory fake (no BPF maps).
	mgr := rules.NewFakeManager()
	mgr.ReconcileConfig(demo.DemoRules())

	// Event hub pumped with synthetic drops.
	hub := events.NewHub(1024, mgr)
	demo.StartFakeEvents(hub)

	apiSrv := &http.Server{
		Addr: *addr,
		Handler: (&api.Server{
			Rules:  mgr,
			Stats:  statsReader,
			Events: hub,
			Iface:  "veth-host (demo)",
			Mode:   "demo",
			ProgID: 0,
		}).Handler(),
	}
	metricsSrv := &http.Server{Addr: *maddr, Handler: metrics.Handler(statsReader)}

	go func() {
		log.Printf("dashboard → http://localhost%s", *addr)
		log.Printf("prometheus → http://localhost%s/metrics", *maddr)
		if err := apiSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("api server: %v", err)
		}
	}()
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("metrics server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
	ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	apiSrv.Shutdown(ctx2)
	metricsSrv.Shutdown(ctx2)
}
