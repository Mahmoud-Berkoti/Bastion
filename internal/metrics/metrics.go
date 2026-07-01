// Package metrics exposes the aggregated data-plane stats as Prometheus
// metrics via a custom collector, so every scrape reads fresh map state.
package metrics

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mberkoti/bastion/internal/stats"
)

type collector struct {
	reader stats.Source
	descs  map[string]*prometheus.Desc
}

func newCollector(r stats.Source) *collector {
	d := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc("bastion_"+name, help, nil, nil)
	}
	return &collector{
		reader: r,
		descs: map[string]*prometheus.Desc{
			"packets_total":         d("packets_total", "Packets seen by the XDP program"),
			"bytes_total":           d("bytes_total", "Bytes seen by the XDP program"),
			"dropped_packets_total": d("dropped_packets_total", "Packets dropped"),
			"dropped_bytes_total":   d("dropped_bytes_total", "Bytes dropped"),
			"passed_total":          d("passed_total", "Packets passed"),
			"drop_blocklist_total":  d("drop_blocklist_total", "Drops from the CIDR blocklist"),
			"drop_port_total":       d("drop_port_total", "Drops from port rules"),
			"drop_ratelimit_total":  d("drop_ratelimit_total", "Drops from rate limiting"),
			"event_drops_total":     d("event_drops_total", "Ring buffer events lost to backpressure"),
		},
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs {
		ch <- d
	}
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	s, err := c.reader.Read()
	if err != nil {
		log.Printf("metrics: reading stats: %v", err)
		return
	}
	counter := func(name string, v uint64) {
		ch <- prometheus.MustNewConstMetric(c.descs[name], prometheus.CounterValue, float64(v))
	}
	counter("packets_total", s.TotalPackets)
	counter("bytes_total", s.TotalBytes)
	counter("dropped_packets_total", s.DroppedPackets)
	counter("dropped_bytes_total", s.DroppedBytes)
	counter("passed_total", s.Passed)
	counter("drop_blocklist_total", s.DropBlocklist)
	counter("drop_port_total", s.DropPort)
	counter("drop_ratelimit_total", s.DropRatelimit)
	counter("event_drops_total", s.EventDrops)
}

// Handler returns an http.Handler serving /metrics for the given source.
func Handler(r stats.Source) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(newCollector(r))
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return mux
}
