package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fleet.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadExample(t *testing.T) {
	c, err := Load("../../deploy/fleet.example.yaml")
	if err != nil {
		t.Fatalf("Load example: %v", err)
	}
	if c.Listen != ":8443" {
		t.Errorf("listen = %q", c.Listen)
	}
	if c.Selection != SelectionPriority {
		t.Errorf("selection = %q", c.Selection)
	}
	if len(c.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(c.Members))
	}
	if c.Health.Interval.Duration != 15*time.Second {
		t.Errorf("interval = %v", c.Health.Interval.Duration)
	}
	if c.Health.Rise != 2 || c.Health.Fall != 3 {
		t.Errorf("rise/fall = %d/%d", c.Health.Rise, c.Health.Fall)
	}
}

func TestDefaultsApplied(t *testing.T) {
	p := writeYAML(t, `
members:
  - label: a
    config_file: /a.json
    check: { type: none }
`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != ":8443" || c.Selection != SelectionPriority {
		t.Errorf("defaults not applied: listen=%q selection=%q", c.Listen, c.Selection)
	}
	if c.Health.Interval.Duration != 15*time.Second || c.Health.SwitchCooldown.Duration != 5*time.Minute {
		t.Errorf("health defaults not applied")
	}
	if c.Members[0].Weight != 1 {
		t.Errorf("weight default = %d, want 1", c.Members[0].Weight)
	}
}

func TestDurationParsing(t *testing.T) {
	p := writeYAML(t, `
health:
  interval: 45s
  flap_window: 2m
members:
  - label: a
    config_file: /a.json
    check: { type: none }
`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Health.Interval.Duration != 45*time.Second {
		t.Errorf("interval = %v", c.Health.Interval.Duration)
	}
	if c.Health.FlapWindow.Duration != 2*time.Minute {
		t.Errorf("flap_window = %v", c.Health.FlapWindow.Duration)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"no members": `selection: priority`,
		"unknown selection": `
selection: bogus
members:
  - {label: a, config_file: /a.json, check: {type: none}}`,
		"unknown check type": `
members:
  - {label: a, config_file: /a.json, check: {type: ping, target: x}}`,
		"missing target": `
members:
  - {label: a, config_file: /a.json, check: {type: tcp}}`,
		"duplicate label": `
members:
  - {label: a, config_file: /a.json, check: {type: none}}
  - {label: a, config_file: /b.json, check: {type: none}}`,
		"missing config_file": `
members:
  - {label: a, check: {type: none}}`,
		"unknown field": `
listen: ":8443"
bogus_key: true
members:
  - {label: a, config_file: /a.json, check: {type: none}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeYAML(t, body)); err == nil {
				t.Fatalf("expected error for %q", name)
			}
		})
	}
}
