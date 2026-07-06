// Package fleet holds the member inventory and the sticky selection that decides
// which member's config /v1/config advertises (DESIGN.md §6).
//
// Selection reads *smoothed* health (never a raw sample) and is deliberately
// sticky: the advertised pick changes only when the current one is genuinely bad
// or a meaningfully better server has recovered and a cooldown has elapsed.
// "Zero switches when everything is fine" is the success condition, not a bug.
package fleet

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"fleetcore/internal/config"
	"fleetcore/internal/health"
)

// ErrNoHealthyMember is returned by Select when no member is up.
var ErrNoHealthyMember = errors.New("no healthy member")

// Member is one fleet server plus the ready-made Amnezia config JSON to serve
// when it is selected. fleetcore never mints crypto; ConfigJSON is exported by
// the operator from their existing setup (DESIGN.md §5.3, Appendix C).
type Member struct {
	Label      string
	Priority   int
	Weight     int
	ConfigJSON []byte
}

// HealthOracle is the smoothed-health view selection consumes. *health.Monitor
// satisfies it; tests inject a fake.
type HealthOracle interface {
	IsUp(label string) bool
	FlapScore(label string) float64
}

// Fleet is the inventory + selection state.
type Fleet struct {
	members  []*Member
	byLabel  map[string]*Member
	oracle   HealthOracle
	strategy string
	cooldown time.Duration
	now      func() time.Time

	mu         sync.Mutex
	current    string
	lastSwitch time.Time
}

// Option configures a Fleet.
type Option func(*Fleet)

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option { return func(f *Fleet) { f.now = now } }

// New builds a Fleet from pre-loaded members and a health oracle (used by tests
// and by Build).
func New(members []*Member, oracle HealthOracle, strategy string, cooldown time.Duration, opts ...Option) *Fleet {
	f := &Fleet{
		byLabel:  make(map[string]*Member, len(members)),
		oracle:   oracle,
		strategy: strategy,
		cooldown: cooldown,
		now:      time.Now,
	}
	for _, m := range members {
		if m.Weight == 0 {
			m.Weight = 1
		}
		f.members = append(f.members, m)
		f.byLabel[m.Label] = m
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

// Build wires a live Fleet from config: it reads every member's config_file and
// constructs the health Monitor. The caller owns the Monitor lifecycle via
// WarmUp/RunHealth.
func Build(cfg *config.Config) (*Fleet, *health.Monitor, error) {
	var members []*Member
	var specs []health.MemberSpec
	for i := range cfg.Members {
		m := &cfg.Members[i]
		blob, err := os.ReadFile(m.ConfigFile)
		if err != nil {
			return nil, nil, fmt.Errorf("member %q: read config_file: %w", m.Label, err)
		}
		if len(blob) == 0 {
			return nil, nil, fmt.Errorf("member %q: config_file %q is empty", m.Label, m.ConfigFile)
		}
		members = append(members, &Member{
			Label:      m.Label,
			Priority:   m.Priority,
			Weight:     m.Weight,
			ConfigJSON: blob,
		})
		checker, err := health.NewChecker(m.Check.Type, m.Check.Target)
		if err != nil {
			return nil, nil, fmt.Errorf("member %q: %w", m.Label, err)
		}
		specs = append(specs, health.MemberSpec{Label: m.Label, Checker: checker})
	}
	mon := health.New(health.Params{
		Interval:   cfg.Health.Interval.Duration,
		Timeout:    cfg.Health.Timeout.Duration,
		FlapWindow: cfg.Health.FlapWindow.Duration,
		Rise:       cfg.Health.Rise,
		Fall:       cfg.Health.Fall,
	}, specs, health.WithLogger(log.Printf))

	f := New(members, mon, cfg.Selection, cfg.Health.SwitchCooldown.Duration)
	return f, mon, nil
}

// Members returns the inventory in configured order.
func (f *Fleet) Members() []*Member { return f.members }

// Member returns the member with the given label, or nil.
func (f *Fleet) Member(label string) *Member { return f.byLabel[label] }

// Current returns the currently advertised label ("" before the first Select).
func (f *Fleet) Current() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current
}

// Select returns the member to advertise now, applying the sticky rules:
//
//   - among up members, rank by strategy (priority default);
//   - if the current pick is unset or down, adopt the best immediately (curative
//     failover);
//   - otherwise keep the current pick unless a meaningfully better member is up
//     AND switch_cooldown has elapsed since the last switch (anti-flap).
func (f *Fleet) Select(now time.Time) (*Member, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	up := make([]*Member, 0, len(f.members))
	for _, m := range f.members {
		if f.oracle.IsUp(m.Label) {
			up = append(up, m)
		}
	}
	if len(up) == 0 {
		return nil, ErrNoHealthyMember
	}

	cur := f.byLabel[f.current]
	curUp := cur != nil && f.oracle.IsUp(cur.Label)

	best := f.best(up, cur)

	// Curative failover: no established pick, or the current one is down.
	if !curUp {
		f.adopt(best, now)
		return best, nil
	}

	// Current is healthy: switch only for a meaningful, cooldown-gated
	// improvement. This is what makes "everything fine => zero switches" hold.
	if f.betterEnough(best, cur) && now.Sub(f.lastSwitch) >= f.cooldown {
		f.adopt(best, now)
		return best, nil
	}
	return cur, nil
}

func (f *Fleet) adopt(m *Member, now time.Time) {
	if f.current != m.Label {
		f.lastSwitch = now
	}
	f.current = m.Label
}

// best returns the top-ranked up member for the active strategy. For roundrobin
// it returns the successor of the current pick (rotation on failover); for
// priority/weighted it returns the head of the ranked order.
func (f *Fleet) best(up []*Member, cur *Member) *Member {
	ranked := f.ranked(up)
	if f.strategy == config.SelectionRoundRobin && cur != nil {
		if next := successor(ranked, cur.Label); next != nil {
			return next
		}
	}
	return ranked[0]
}

// ranked orders up members best-first for the active strategy. flapScore always
// participates so a flapping node is never picked as best within its tier.
func (f *Fleet) ranked(up []*Member) []*Member {
	out := make([]*Member, len(up))
	copy(out, up)
	flap := func(m *Member) float64 { return f.oracle.FlapScore(m.Label) }
	switch f.strategy {
	case config.SelectionWeighted:
		sort.SliceStable(out, func(i, j int) bool {
			a, b := out[i], out[j]
			if a.Priority != b.Priority {
				return a.Priority < b.Priority
			}
			if a.Weight != b.Weight {
				return a.Weight > b.Weight // heavier first
			}
			if fa, fb := flap(a), flap(b); fa != fb {
				return fa < fb
			}
			return a.Label < b.Label
		})
	case config.SelectionRoundRobin:
		sort.SliceStable(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	default: // priority
		sort.SliceStable(out, func(i, j int) bool {
			a, b := out[i], out[j]
			if a.Priority != b.Priority {
				return a.Priority < b.Priority
			}
			if fa, fb := flap(a), flap(b); fa != fb {
				return fa < fb
			}
			if a.Weight != b.Weight {
				return a.Weight > b.Weight
			}
			return a.Label < b.Label
		})
	}
	return out
}

// betterEnough decides whether switching away from a *healthy* current pick is
// justified. It intentionally ignores flapScore noise: only a real tier (or, for
// weighted, weight) improvement clears the bar. Full margin/durability gating is
// DESIGN.md rule 5 (M3).
func (f *Fleet) betterEnough(best, cur *Member) bool {
	if best.Label == cur.Label {
		return false
	}
	if best.Priority < cur.Priority {
		return true
	}
	if f.strategy == config.SelectionWeighted &&
		best.Priority == cur.Priority && best.Weight > cur.Weight {
		return true
	}
	return false
}

// successor returns the member after label in ranked order, wrapping around.
func successor(ranked []*Member, label string) *Member {
	if len(ranked) == 0 {
		return nil
	}
	idx := -1
	for i, m := range ranked {
		if m.Label == label {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ranked[0]
	}
	return ranked[(idx+1)%len(ranked)]
}
