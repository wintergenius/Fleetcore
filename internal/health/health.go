// Package health implements the smoothed health state machine and the probes
// that feed it (DESIGN.md §6).
//
// The hard-won lesson baked in here is anti-churn: a member goes down only after
// a *window* of consecutive failures (fall), and comes back up only after a
// window of successes (rise). One dropped packet never flips state, and a member
// that oscillates accrues a decaying flapScore so selection can avoid it. This
// is what keeps failover from turning into flap.
package health

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"sync"
	"time"
)

// State is a member's smoothed liveness.
type State int

const (
	StateDown State = iota
	StateUp
)

func (s State) String() string {
	if s == StateUp {
		return "up"
	}
	return "down"
}

// Params are the state-machine tunables, mirrored from config.Health so this
// package stays independent of the config format.
type Params struct {
	Interval   time.Duration
	Timeout    time.Duration
	FlapWindow time.Duration
	Rise       int
	Fall       int
}

// Checker performs one liveness probe. A nil error means the member answered.
type Checker interface {
	Probe(ctx context.Context) error
}

// MemberSpec binds a label to its checker.
type MemberSpec struct {
	Label   string
	Checker Checker
}

// MemberHealth is an immutable snapshot of one member's health, for /healthz.
type MemberHealth struct {
	Label      string    `json:"label"`
	State      string    `json:"state"`
	Up         bool      `json:"up"`
	OkStreak   int       `json:"ok_streak"`
	FailStreak int       `json:"fail_streak"`
	FlapScore  float64   `json:"flap_score"`
	LastError  string    `json:"last_error,omitempty"`
	LastProbe  time.Time `json:"last_probe,omitempty"`
}

// memberState is the mutable per-member machine. Guarded by Monitor.mu.
type memberState struct {
	label      string
	checker    Checker
	state      State
	okStreak   int
	failStreak int
	flapScore  float64
	lastDecay  time.Time
	lastErr    string
	lastProbe  time.Time
}

// observe advances the machine by one probe result and returns the state after.
func (m *memberState) observe(ok bool, now time.Time, p Params) State {
	m.decayFlap(now, p.FlapWindow)
	if ok {
		m.failStreak = 0
		m.okStreak++
		if m.state == StateDown && m.okStreak >= p.Rise {
			m.state = StateUp
		}
	} else {
		m.okStreak = 0
		m.failStreak++
		if m.state == StateUp && m.failStreak >= p.Fall {
			m.state = StateDown
			m.flapScore++ // penalise the up->down flip
		}
	}
	m.lastProbe = now
	return m.state
}

// seed sets an established initial state from the first probe, so the service
// reflects reality immediately instead of waiting out rise/fall at startup.
func (m *memberState) seed(ok bool, now time.Time, p Params) {
	if ok {
		m.state = StateUp
		m.okStreak = p.Rise
		m.failStreak = 0
	} else {
		m.state = StateDown
		m.failStreak = p.Fall
		m.okStreak = 0
	}
	m.lastDecay = now
	m.lastProbe = now
}

// decayFlap exponentially decays flapScore toward zero over flap_window, so a
// node that stops flapping is forgiven and can be selected again.
func (m *memberState) decayFlap(now time.Time, window time.Duration) {
	if m.lastDecay.IsZero() {
		m.lastDecay = now
		return
	}
	dt := now.Sub(m.lastDecay)
	if dt <= 0 || window <= 0 {
		return
	}
	m.flapScore *= math.Exp(-dt.Seconds() / window.Seconds())
	if m.flapScore < 1e-6 {
		m.flapScore = 0
	}
	m.lastDecay = now
}

func (m *memberState) snapshot() MemberHealth {
	return MemberHealth{
		Label:      m.label,
		State:      m.state.String(),
		Up:         m.state == StateUp,
		OkStreak:   m.okStreak,
		FailStreak: m.failStreak,
		FlapScore:  m.flapScore,
		LastError:  m.lastErr,
		LastProbe:  m.lastProbe,
	}
}

// Monitor runs one probe loop per member and exposes their smoothed health.
type Monitor struct {
	mu      sync.RWMutex
	members map[string]*memberState
	order   []string
	params  Params
	now     func() time.Time
	logf    func(format string, args ...any)
}

// Option configures a Monitor.
type Option func(*Monitor)

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option { return func(m *Monitor) { m.now = now } }

// WithLogger sets the state-transition logger.
func WithLogger(logf func(string, ...any)) Option { return func(m *Monitor) { m.logf = logf } }

// New builds a Monitor for the given members. All start down until WarmUp or the
// first probe result seeds them.
func New(p Params, specs []MemberSpec, opts ...Option) *Monitor {
	mon := &Monitor{
		members: make(map[string]*memberState, len(specs)),
		params:  p,
		now:     time.Now,
		logf:    func(string, ...any) {},
	}
	for _, s := range specs {
		mon.members[s.Label] = &memberState{label: s.Label, checker: s.Checker}
		mon.order = append(mon.order, s.Label)
	}
	for _, o := range opts {
		o(mon)
	}
	return mon
}

// WarmUp probes every member once, synchronously, and seeds its state from the
// result. Call before serving so the first /v1/config reflects reality.
func (mon *Monitor) WarmUp(ctx context.Context) {
	var wg sync.WaitGroup
	for _, label := range mon.order {
		ms := mon.members[label]
		wg.Add(1)
		go func(ms *memberState) {
			defer wg.Done()
			ok, errStr := mon.probe(ctx, ms.checker)
			now := mon.now()
			mon.mu.Lock()
			ms.seed(ok, now, mon.params)
			ms.lastErr = errStr
			mon.mu.Unlock()
		}(ms)
	}
	wg.Wait()
}

// Run launches the periodic probe loops and blocks until ctx is cancelled.
func (mon *Monitor) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, label := range mon.order {
		ms := mon.members[label]
		wg.Add(1)
		go func(ms *memberState) {
			defer wg.Done()
			mon.loop(ctx, ms)
		}(ms)
	}
	wg.Wait()
}

func (mon *Monitor) loop(ctx context.Context, ms *memberState) {
	ticker := time.NewTicker(mon.params.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok, errStr := mon.probe(ctx, ms.checker)
			now := mon.now()
			mon.mu.Lock()
			prev := ms.state
			next := ms.observe(ok, now, mon.params)
			ms.lastErr = errStr
			flap := ms.flapScore // read under the lock for the log line below
			mon.mu.Unlock()
			if prev != next {
				// ms.label is immutable after construction; flap was snapshotted.
				mon.logf("health: %s %s -> %s (flap=%.2f)", ms.label, prev, next, flap)
			}
		}
	}
}

// probe runs one checker call bounded by the configured timeout.
func (mon *Monitor) probe(ctx context.Context, c Checker) (ok bool, errStr string) {
	cctx, cancel := context.WithTimeout(ctx, mon.params.Timeout)
	defer cancel()
	if err := c.Probe(cctx); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// IsUp reports whether the member is currently up. Unknown labels are down.
func (mon *Monitor) IsUp(label string) bool {
	mon.mu.RLock()
	defer mon.mu.RUnlock()
	ms, ok := mon.members[label]
	return ok && ms.state == StateUp
}

// FlapScore returns the member's decayed flap score (0 for unknown labels).
func (mon *Monitor) FlapScore(label string) float64 {
	mon.mu.RLock()
	defer mon.mu.RUnlock()
	if ms, ok := mon.members[label]; ok {
		return ms.flapScore
	}
	return 0
}

// Snapshot returns a stable-ordered copy of every member's health.
func (mon *Monitor) Snapshot() []MemberHealth {
	mon.mu.RLock()
	defer mon.mu.RUnlock()
	out := make([]MemberHealth, 0, len(mon.order))
	for _, label := range mon.order {
		out = append(out, mon.members[label].snapshot())
	}
	return out
}

// --- Checkers -------------------------------------------------------------

// NewChecker builds a Checker from a check type + target (DESIGN.md §7).
// Types: none, tcp, udp, http, handshake. handshake is a coarse TCP-connect
// liveness proxy for now; a real AWG/WG handshake probe is M2+.
func NewChecker(checkType, target string) (Checker, error) {
	switch checkType {
	case "none", "":
		return noneChecker{}, nil
	case "tcp", "handshake":
		return &tcpChecker{target: target}, nil
	case "udp":
		return &udpChecker{target: target}, nil
	case "http":
		return &httpChecker{url: target}, nil
	default:
		return nil, errors.New("unknown check type: " + checkType)
	}
}

// noneChecker always succeeds — "no probe, always up".
type noneChecker struct{}

func (noneChecker) Probe(context.Context) error { return nil }

// tcpChecker connects and immediately closes.
type tcpChecker struct{ target string }

func (c *tcpChecker) Probe(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.target)
	if err != nil {
		return err
	}
	return conn.Close()
}

// udpChecker is best-effort: UDP is connectionless, so we send a probe byte and
// look for an ICMP "port unreachable" surfacing as a read error. A timeout is
// treated as *up* because silence is the normal case for a healthy UDP service.
type udpChecker struct{ target string }

func (c *udpChecker) Probe(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", c.target)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return err
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		return nil // got a reply
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return nil // silence: assume the port is open (best-effort)
	}
	return err // e.g. connection refused (ICMP port unreachable)
}

// httpChecker GETs a URL and treats any status < 400 as up.
type httpChecker struct{ url string }

func (c *httpChecker) Probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return errors.New("health: HTTP status " + resp.Status)
	}
	return nil
}
