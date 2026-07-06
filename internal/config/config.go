// Package config loads and validates fleet.yaml (DESIGN.md §7).
package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Selection strategies (DESIGN.md §6). priority is the default.
const (
	SelectionPriority   = "priority"
	SelectionWeighted   = "weighted"
	SelectionRoundRobin = "roundrobin"
)

// Check types (DESIGN.md §7). "none" means "no probe, always up" — handy for a
// local demo where the real servers aren't reachable.
const (
	CheckNone      = "none"
	CheckTCP       = "tcp"
	CheckUDP       = "udp"
	CheckHTTP      = "http"
	CheckHandshake = "handshake"
)

// Config is the whole fleet.yaml document.
type Config struct {
	Listen    string   `yaml:"listen"`
	Selection string   `yaml:"selection"`
	Health    Health   `yaml:"health"`
	Signing   Signing  `yaml:"signing"`
	Members   []Member `yaml:"members"`
}

// Health holds the smoothed-state-machine tunables (DESIGN.md §6).
type Health struct {
	Interval       Duration `yaml:"interval"`
	Timeout        Duration `yaml:"timeout"`
	Rise           int      `yaml:"rise"`
	Fall           int      `yaml:"fall"`
	FlapWindow     Duration `yaml:"flap_window"`
	SwitchCooldown Duration `yaml:"switch_cooldown"`
}

// Signing points at the mounted private key and its key id.
type Signing struct {
	KeyFile string `yaml:"key_file"`
	Kid     string `yaml:"kid"`
}

// Member is one fleet server: how to health-check it and which decoded Amnezia
// config JSON to serve when it is selected.
type Member struct {
	Label      string `yaml:"label"`
	Priority   int    `yaml:"priority"`
	Weight     int    `yaml:"weight"`
	Check      Check  `yaml:"check"`
	ConfigFile string `yaml:"config_file"`
}

// Check describes one health probe.
type Check struct {
	Type   string `yaml:"type"`
	Target string `yaml:"target"`
}

// Duration is a time.Duration that unmarshals from a Go duration string
// ("15s", "10m"); yaml.v3 does not handle time.Duration natively.
type Duration struct{ time.Duration }

// UnmarshalYAML parses "15s"-style strings (and plain-number seconds).
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		dur, perr := time.ParseDuration(s)
		if perr != nil {
			return fmt.Errorf("invalid duration %q: %w", s, perr)
		}
		d.Duration = dur
		return nil
	}
	var secs float64
	if err := value.Decode(&secs); err != nil {
		return fmt.Errorf("duration must be a string like \"15s\" or a number of seconds")
	}
	d.Duration = time.Duration(secs * float64(time.Second))
	return nil
}

// Load reads, parses, defaults, and validates a fleet.yaml file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // reject typos in fleet.yaml rather than silently ignoring
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.Selection == "" {
		c.Selection = SelectionPriority
	}
	if c.Health.Interval.Duration == 0 {
		c.Health.Interval.Duration = 15 * time.Second
	}
	if c.Health.Timeout.Duration == 0 {
		c.Health.Timeout.Duration = 3 * time.Second
	}
	if c.Health.Rise == 0 {
		c.Health.Rise = 2
	}
	if c.Health.Fall == 0 {
		c.Health.Fall = 3
	}
	if c.Health.FlapWindow.Duration == 0 {
		c.Health.FlapWindow.Duration = 10 * time.Minute
	}
	if c.Health.SwitchCooldown.Duration == 0 {
		c.Health.SwitchCooldown.Duration = 5 * time.Minute
	}
	for i := range c.Members {
		if c.Members[i].Weight == 0 {
			c.Members[i].Weight = 1
		}
		if c.Members[i].Check.Type == "" {
			c.Members[i].Check.Type = CheckNone
		}
	}
}

// Validate enforces the constraints a running server needs. It does not require
// the signing key (some subcommands, e.g. a dry validate, don't need it) — that
// is checked at serve time.
func (c *Config) Validate() error {
	switch c.Selection {
	case SelectionPriority, SelectionWeighted, SelectionRoundRobin:
	default:
		return fmt.Errorf("selection: unknown strategy %q (want priority|weighted|roundrobin)", c.Selection)
	}
	if c.Health.Rise < 1 {
		return fmt.Errorf("health.rise must be >= 1")
	}
	if c.Health.Fall < 2 {
		return fmt.Errorf("health.fall must be >= 2 so a single missed probe never marks a member down (DESIGN §6 rule 1)")
	}
	if c.Health.Interval.Duration <= 0 {
		return fmt.Errorf("health.interval must be > 0")
	}
	if c.Health.Timeout.Duration <= 0 {
		return fmt.Errorf("health.timeout must be > 0")
	}
	if c.Health.FlapWindow.Duration <= 0 {
		return fmt.Errorf("health.flap_window must be > 0")
	}
	if c.Health.SwitchCooldown.Duration < 0 {
		return fmt.Errorf("health.switch_cooldown must be >= 0")
	}
	if len(c.Members) == 0 {
		return fmt.Errorf("no members configured")
	}
	seen := map[string]bool{}
	for i, m := range c.Members {
		if m.Label == "" {
			return fmt.Errorf("members[%d]: label is required", i)
		}
		if seen[m.Label] {
			return fmt.Errorf("members[%d]: duplicate label %q", i, m.Label)
		}
		seen[m.Label] = true
		if m.ConfigFile == "" {
			return fmt.Errorf("member %q: config_file is required", m.Label)
		}
		switch m.Check.Type {
		case CheckNone:
		case CheckTCP, CheckUDP, CheckHTTP, CheckHandshake:
			if m.Check.Target == "" {
				return fmt.Errorf("member %q: check.target is required for type %q", m.Label, m.Check.Type)
			}
		default:
			return fmt.Errorf("member %q: unknown check type %q", m.Label, m.Check.Type)
		}
	}
	return nil
}

// Member returns the member with the given label, or nil.
func (c *Config) Member(label string) *Member {
	for i := range c.Members {
		if c.Members[i].Label == label {
			return &c.Members[i]
		}
	}
	return nil
}
