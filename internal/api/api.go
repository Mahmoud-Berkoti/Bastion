// Package api serves the REST control API, the live event stream (SSE),
// and the embedded web dashboard.
package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/mberkoti/bastion/internal/events"
	"github.com/mberkoti/bastion/internal/rules"
	"github.com/mberkoti/bastion/internal/stats"
)

//go:embed web
var webFS embed.FS

// maxBodyBytes limits POST/DELETE request bodies to prevent memory abuse.
const maxBodyBytes = 64 * 1024 // 64 KiB — more than enough for any rule payload

// maxEventsLimit caps the ?limit= query parameter on GET /events.
const maxEventsLimit = 1000

// apiRateLimit allows at most burstAPI requests per second per IP.
const (
	burstAPI      = 50
	windowSeconds = 1
)

type Server struct {
	Rules  rules.Manager
	Stats  stats.Source
	Events *events.Hub
	Iface  string
	Mode   string
	ProgID uint32
}

func (s *Server) Handler() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		// The embedded FS is baked into the binary at compile time; a
		// missing "web" directory is a build error, not a runtime one.
		panic(fmt.Sprintf("api: embedded web assets missing: %v", err))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	mux.HandleFunc("GET /api/v1/rules", s.handleGetRules)
	mux.HandleFunc("POST /api/v1/rules", s.handlePostRule)
	mux.HandleFunc("DELETE /api/v1/rules", s.handleDeleteRule)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/events/stream", s.handleEventStream)
	mux.Handle("GET /", http.FileServerFS(sub))

	return securityHeaders(rateLimiter(mux))
}

// securityHeaders adds defensive HTTP headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

// rateLimiter is a simple per-IP sliding-window limiter (no external deps).
// It allows up to burstAPI requests per windowSeconds. Fine for a local
// control-plane tool; replace with a proper middleware if exposed publicly.
type ipBucket struct {
	count int
	reset time.Time
}

var (
	rlMu     sync.Mutex
	rlBuckets = map[string]*ipBucket{}
)

func rateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		now := time.Now()

		rlMu.Lock()
		b, ok := rlBuckets[ip]
		if !ok || now.After(b.reset) {
			b = &ipBucket{reset: now.Add(windowSeconds * time.Second)}
			rlBuckets[ip] = b
		}
		b.count++
		over := b.count > burstAPI
		rlMu.Unlock()

		if over {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// No-store on all API responses: stats/rules are live and must not be
	// served stale from a cache or browser back-button.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeClientErr returns the error string to the caller — it came from
// validated input, so it's safe to expose.
func writeClientErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// writeServerErr logs the full error internally but returns a generic
// message to the caller so implementation details don't leak.
func writeServerErr(w http.ResponseWriter, err error) {
	log.Printf("api: internal error: %v", err)
	writeJSON(w, http.StatusInternalServerError,
		map[string]string{"error": "internal server error"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"iface":   s.Iface,
		"mode":    s.Mode,
		"prog_id": s.ProgID,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.Stats.Read()
	if err != nil {
		writeServerErr(w, err) // BPF map errors must not reach the client
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Rules.Snapshot())
}

// ruleRequest is the body for POST and DELETE /api/v1/rules.
// type selects which fields matter:
//
//	{"type":"blocklist","cidr":"10.0.0.5/32"}
//	{"type":"port","proto":"tcp","port":2222,"action":"drop"}
//	{"type":"ratelimit","cidr":"10.0.0.0/24","pps":1000,"burst":200}
type ruleRequest struct {
	Type   string `json:"type"`
	CIDR   string `json:"cidr,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Port   uint16 `json:"port,omitempty"`
	Action string `json:"action,omitempty"`
	PPS    uint64 `json:"pps,omitempty"`
	Burst  uint64 `json:"burst,omitempty"`
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(dst); err != nil {
		writeClientErr(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func (s *Server) handlePostRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var err error
	switch req.Type {
	case "blocklist":
		err = s.Rules.AddBlocklist(req.CIDR)
	case "port":
		if req.Action == "" {
			req.Action = "drop"
		}
		err = s.Rules.AddPortRule(rules.PortRule{Proto: req.Proto, Port: req.Port, Action: req.Action})
	case "ratelimit":
		err = s.Rules.AddRateLimit(rules.RateLimit{CIDR: req.CIDR, PPS: req.PPS, Burst: req.Burst})
	default:
		err = fmt.Errorf("unknown rule type %q (blocklist|port|ratelimit)", req.Type)
	}
	if err != nil {
		writeClientErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.Rules.Snapshot())
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var err error
	switch req.Type {
	case "blocklist":
		err = s.Rules.RemoveBlocklist(req.CIDR)
	case "port":
		err = s.Rules.RemovePortRule(req.Proto, req.Port)
	case "ratelimit":
		err = s.Rules.RemoveRateLimit(req.CIDR)
	default:
		err = fmt.Errorf("unknown rule type %q (blocklist|port|ratelimit)", req.Type)
	}
	if err != nil {
		writeClientErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.Rules.Snapshot())
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			if n > maxEventsLimit {
				n = maxEventsLimit
			}
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, s.Events.Recent(limit))
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeServerErr(w, fmt.Errorf("streaming unsupported by response writer"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering

	ch, cancel := s.Events.Subscribe()
	defer cancel()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
