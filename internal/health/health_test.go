package health

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testParams = Params{Rise: 2, Fall: 3, FlapWindow: 10 * time.Minute}

// A single failure must NOT flip a healthy member (no single-probe truth).
func TestNoSingleProbeTruth(t *testing.T) {
	t0 := time.Unix(0, 0)
	m := &memberState{label: "x"}
	m.seed(true, t0, testParams)
	if m.observe(false, t0, testParams) != StateUp {
		t.Fatal("one failure flipped the member down")
	}
}

// fall consecutive failures flip up->down and bump flapScore; rise successes
// flip back.
func TestHysteresis(t *testing.T) {
	t0 := time.Unix(0, 0)
	m := &memberState{label: "x"}
	m.seed(true, t0, testParams)

	// fall-1 failures keep it up.
	for i := 0; i < testParams.Fall-1; i++ {
		if got := m.observe(false, t0, testParams); got != StateUp {
			t.Fatalf("failure %d flipped early to %v", i+1, got)
		}
	}
	// fall-th failure flips down.
	if got := m.observe(false, t0, testParams); got != StateDown {
		t.Fatalf("did not flip down after %d failures: %v", testParams.Fall, got)
	}
	if m.flapScore != 1 {
		t.Fatalf("flapScore = %v, want 1 after one up->down flip", m.flapScore)
	}

	// rise-1 successes keep it down.
	for i := 0; i < testParams.Rise-1; i++ {
		if got := m.observe(true, t0, testParams); got != StateDown {
			t.Fatalf("success %d flipped up early: %v", i+1, got)
		}
	}
	// rise-th success flips up.
	if got := m.observe(true, t0, testParams); got != StateUp {
		t.Fatalf("did not flip up after %d successes: %v", testParams.Rise, got)
	}
}

func TestFlapDecay(t *testing.T) {
	t0 := time.Unix(0, 0)
	m := &memberState{label: "x", flapScore: 2, lastDecay: t0}
	m.decayFlap(t0.Add(10*time.Minute), 10*time.Minute)
	want := 2 * math.Exp(-1)
	if math.Abs(m.flapScore-want) > 1e-9 {
		t.Fatalf("flapScore = %v, want %v", m.flapScore, want)
	}
}

func TestNewCheckerUnknown(t *testing.T) {
	if _, err := NewChecker("bogus", "x"); err == nil {
		t.Fatal("expected error for unknown check type")
	}
	if c, err := NewChecker("none", ""); err != nil || c == nil {
		t.Fatalf("none checker: %v", err)
	}
}

func TestTCPChecker(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	c := &tcpChecker{target: ln.Addr().String()}
	if err := c.Probe(context.Background()); err != nil {
		t.Fatalf("probe live listener: %v", err)
	}

	ln.Close() // now nothing is listening
	dead := &tcpChecker{target: ln.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dead.Probe(ctx); err == nil {
		t.Fatal("probe of closed port unexpectedly succeeded")
	}
}

// flagChecker fails iff its flag is set, so a test can flip a member's liveness.
type flagChecker struct{ fail atomic.Bool }

func (c *flagChecker) Probe(context.Context) error {
	if c.fail.Load() {
		return errors.New("down")
	}
	return nil
}

func eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestMonitorProbeWiring drives the real probe -> observe -> IsUp path through
// Run (not just memberState in isolation), proving IsUp reflects the smoothed
// state the probe loop maintains (DESIGN §6 rule 6).
func TestMonitorProbeWiring(t *testing.T) {
	chk := &flagChecker{}
	p := Params{Interval: 5 * time.Millisecond, Timeout: time.Second, FlapWindow: time.Minute, Rise: 2, Fall: 3}
	mon := New(p, []MemberSpec{{Label: "m", Checker: chk}})
	mon.WarmUp(context.Background())
	if !mon.IsUp("m") {
		t.Fatal("member not up after warm-up")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mon.Run(ctx)

	chk.fail.Store(true)
	if !eventually(2*time.Second, func() bool { return !mon.IsUp("m") }) {
		t.Fatal("member did not go down after sustained failing probes")
	}
	chk.fail.Store(false)
	if !eventually(2*time.Second, func() bool { return mon.IsUp("m") }) {
		t.Fatal("member did not recover after sustained ok probes")
	}
}

// TestMonitorConcurrent overlaps the probe-loop writers with reader calls; run
// under `go test -race` it catches a dropped lock on the health state.
func TestMonitorConcurrent(t *testing.T) {
	p := Params{Interval: time.Millisecond, Timeout: time.Second, FlapWindow: time.Minute, Rise: 2, Fall: 3}
	mon := New(p, []MemberSpec{
		{Label: "a", Checker: noneChecker{}},
		{Label: "b", Checker: &flagChecker{}},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); mon.Run(ctx) }()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				_ = mon.IsUp("a")
				_ = mon.FlapScore("b")
				_ = mon.Snapshot()
			}
		}()
	}
	wg.Wait()
}

// WarmUp seeds state from a single synchronous probe of each member.
func TestMonitorWarmUp(t *testing.T) {
	// A member whose "none" check always passes must be up after warm-up.
	mon := New(testParams, []MemberSpec{{Label: "always", Checker: noneChecker{}}})
	mon.WarmUp(context.Background())
	if !mon.IsUp("always") {
		t.Fatal("none-checked member not up after WarmUp")
	}
	if mon.IsUp("missing") {
		t.Fatal("unknown label reported up")
	}
}
