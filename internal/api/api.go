// Package api serves the REST control API, the live event stream (SSE),
// and the embedded web dashboard.
package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"

	"github.com/mberkoti/bastion/internal/events"
	"github.com/mberkoti/bastion/internal/rules"
	"github.com/mberkoti/bastion/internal/stats"
)

//go:embed web
var webFS embed.FS

type Server struct {
	Rules  *rules.Manager
	Stats  *stats.Reader
	Events *events.Hub
	// Info reported at /api/v1/status for sanity checks (e.g. verifying
	// the prog id is unchanged across live rule updates).
	Iface  string
	Mode   string
	ProgID uint32
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	mux.HandleFunc("GET /api/v1/rules", s.handleGetRules)
	mux.HandleFunc("POST /api/v1/rules", s.handlePostRule)
	mux.HandleFunc("DELETE /api/v1/rules", s.handleDeleteRule)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/events/stream", s.handleEventStream)

	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(sub))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
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
		writeErr(w, http.StatusInternalServerError, err)
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

func (s *Server) handlePostRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
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
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.Rules.Snapshot())
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
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
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.Rules.Snapshot())
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, s.Events.Recent(limit))
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

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
