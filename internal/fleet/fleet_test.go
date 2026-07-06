package fleet

import (
	"errors"
	"testing"
	"time"

	"fleetcore/internal/config"
)

type oracle struct {
	up   map[string]bool
	flap map[string]float64
}

func (o *oracle) IsUp(l string) bool         { return o.up[l] }
func (o *oracle) FlapScore(l string) float64 { return o.flap[l] }

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func members() []*Member {
	return []*Member{
		{Label: "nl-1", Priority: 10, Weight: 1, ConfigJSON: []byte(`{"m":"nl"}`)},
		{Label: "de-1", Priority: 20, Weight: 1, ConfigJSON: []byte(`{"m":"de"}`)},
	}
}

func mustSelect(t *testing.T, f *Fleet, now time.Time) *Member {
	t.Helper()
	m, err := f.Select(now)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	return m
}

// Lowest priority number wins.
func TestPriorityPick(t *testing.T) {
	o := &oracle{up: map[string]bool{"nl-1": true, "de-1": true}}
	f := New(members(), o, config.SelectionPriority, 5*time.Minute)
	if got := mustSelect(t, f, time.Unix(0, 0)); got.Label != "nl-1" {
		t.Fatalf("picked %s, want nl-1", got.Label)
	}
}

// A flapping same-priority member is ranked behind a stable one.
func TestFlapScoreRanking(t *testing.T) {
	m := []*Member{
		{Label: "a", Priority: 10, Weight: 1},
		{Label: "b", Priority: 10, Weight: 1},
	}
	o := &oracle{up: map[string]bool{"a": true, "b": true}, flap: map[string]float64{"a": 5}}
	f := New(m, o, config.SelectionPriority, 0)
	if got := mustSelect(t, f, time.Unix(0, 0)); got.Label != "b" {
		t.Fatalf("picked %s, want b (a is flapping)", got.Label)
	}
}

// Current down => switch immediately to the best up member (curative failover).
func TestCurativeFailover(t *testing.T) {
	o := &oracle{up: map[string]bool{"nl-1": false, "de-1": true}}
	f := New(members(), o, config.SelectionPriority, 5*time.Minute)
	if got := mustSelect(t, f, time.Unix(0, 0)); got.Label != "de-1" {
		t.Fatalf("picked %s, want de-1", got.Label)
	}
}

// Everything fine => zero switches on repeated polls.
func TestStickyNoChurn(t *testing.T) {
	o := &oracle{up: map[string]bool{"nl-1": true, "de-1": true}}
	clk := &clock{t: time.Unix(0, 0)}
	f := New(members(), o, config.SelectionPriority, 5*time.Minute, WithClock(clk.now))
	first := mustSelect(t, f, clk.t)
	clk.t = clk.t.Add(1 * time.Hour)
	second := mustSelect(t, f, clk.t)
	if first.Label != second.Label {
		t.Fatalf("advertised pick changed with no health change: %s -> %s", first.Label, second.Label)
	}
	if f.Current() != "nl-1" {
		t.Fatalf("Current = %s", f.Current())
	}
}

// Failback to a recovered higher-priority member waits out switch_cooldown.
func TestFailbackAfterCooldown(t *testing.T) {
	o := &oracle{up: map[string]bool{"nl-1": false, "de-1": true}}
	clk := &clock{t: time.Unix(0, 0)}
	f := New(members(), o, config.SelectionPriority, 5*time.Minute, WithClock(clk.now))

	if got := mustSelect(t, f, clk.t); got.Label != "de-1" {
		t.Fatalf("initial pick %s, want de-1", got.Label)
	}
	o.up["nl-1"] = true // higher-priority server recovers

	clk.t = clk.t.Add(1 * time.Minute) // still within cooldown
	if got := mustSelect(t, f, clk.t); got.Label != "de-1" {
		t.Fatalf("switched before cooldown: got %s", got.Label)
	}
	clk.t = clk.t.Add(5 * time.Minute) // now past cooldown
	if got := mustSelect(t, f, clk.t); got.Label != "nl-1" {
		t.Fatalf("did not fail back after cooldown: got %s", got.Label)
	}
}

func TestNoHealthyMember(t *testing.T) {
	o := &oracle{up: map[string]bool{"nl-1": false, "de-1": false}}
	f := New(members(), o, config.SelectionPriority, 0)
	if _, err := f.Select(time.Unix(0, 0)); !errors.Is(err, ErrNoHealthyMember) {
		t.Fatalf("err = %v, want ErrNoHealthyMember", err)
	}
}

// Round-robin advances to the next member on each failover.
func TestRoundRobinRotation(t *testing.T) {
	m := []*Member{
		{Label: "a", Priority: 10}, {Label: "b", Priority: 10}, {Label: "c", Priority: 10},
	}
	o := &oracle{up: map[string]bool{"a": true, "b": true, "c": true}}
	f := New(m, o, config.SelectionRoundRobin, 0)

	if got := mustSelect(t, f, time.Unix(0, 0)); got.Label != "a" {
		t.Fatalf("first = %s, want a", got.Label)
	}
	o.up["a"] = false
	if got := mustSelect(t, f, time.Unix(1, 0)); got.Label != "b" {
		t.Fatalf("after a down = %s, want b", got.Label)
	}
	o.up["b"] = false
	if got := mustSelect(t, f, time.Unix(2, 0)); got.Label != "c" {
		t.Fatalf("after b down = %s, want c", got.Label)
	}
}
