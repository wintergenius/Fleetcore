// Package api assembles the signed response envelope (DESIGN.md §5.2) and serves
// the three endpoints: /v1/config, /v1/pubkey, /healthz.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"fleetcore/internal/fleet"
	"fleetcore/internal/health"
	"fleetcore/internal/sign"
	"fleetcore/internal/vpnblob"
)

// Alg is the signature algorithm advertised in the envelope. A client must
// reject unknown alg values (DESIGN.md D.2). M3 adds "ed25519-ts".
const Alg = "ed25519"

// Envelope is the GET /v1/config response (DESIGN.md §5.2). The signature covers
// the exact UTF-8 bytes of Config (including the "vpn://" prefix), so unknown
// fields here stay backward-compatible with today's client parser.
type Envelope struct {
	Config string `json:"config"`
	Sig    string `json:"sig"`
	Alg    string `json:"alg"`
	Kid    string `json:"kid"`
	Ts     int64  `json:"ts"`
}

// Snapshotter exposes per-member health for /healthz (satisfied by
// *health.Monitor). Optional — nil yields a bare liveness response.
type Snapshotter interface {
	Snapshot() []health.MemberHealth
}

// Server holds everything the handlers need.
type Server struct {
	fleet    *fleet.Fleet
	signer   *sign.Signer
	health   Snapshotter
	now      func() time.Time
	compress bool
}

// Option configures a Server.
type Option func(*Server)

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// WithHealth attaches a health snapshot source for /healthz.
func WithHealth(h Snapshotter) Option { return func(s *Server) { s.health = h } }

// WithCompress enables Qt qCompress framing of the payload (DESIGN.md D.4).
func WithCompress(on bool) Option { return func(s *Server) { s.compress = on } }

// NewServer builds a Server.
func NewServer(f *fleet.Fleet, signer *sign.Signer, opts ...Option) *Server {
	s := &Server{fleet: f, signer: signer, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Handler returns the routed http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/config", s.handleConfig)
	mux.HandleFunc("/v1/pubkey", s.handlePubkey)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m, err := s.fleet.Select(s.now())
	if err != nil {
		if errors.Is(err, fleet.ErrNoHealthyMember) {
			http.Error(w, "no healthy member", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "selection error", http.StatusInternalServerError)
		return
	}

	var configStr string
	if s.compress {
		configStr, err = vpnblob.EncodeCompressed(m.ConfigJSON)
		if err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
			return
		}
	} else {
		configStr = vpnblob.Encode(m.ConfigJSON)
	}

	env := Envelope{
		Config: configStr,
		Sig:    s.signer.SignConfig(configStr),
		Alg:    Alg,
		Kid:    s.signer.Kid,
		Ts:     s.now().Unix(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(env)
}

func (s *Server) handlePubkey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, sign.PublicKeyString(s.signer.PublicKey())+"\n")
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := struct {
		Status  string                `json:"status"`
		Current string                `json:"current,omitempty"`
		Members []health.MemberHealth `json:"members,omitempty"`
	}{Status: "ok", Current: s.fleet.Current()}
	if s.health != nil {
		resp.Members = s.health.Snapshot()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
