package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"fleetcore/internal/fleet"
	"fleetcore/internal/sign"
	"fleetcore/internal/vpnblob"
)

// fakeOracle lets a test pin member health without running real probes.
type fakeOracle struct {
	up   map[string]bool
	flap map[string]float64
}

func (o fakeOracle) IsUp(label string) bool         { return o.up[label] }
func (o fakeOracle) FlapScore(label string) float64 { return o.flap[label] }

const fixtureNL1 = "../../deploy/fleet/nl-1.amnezia.json"

// newTestServer builds a one-member server serving the nl-1 fixture, plus the
// keypair a client would pin at import time. Extra Options (e.g. WithCompress)
// are appended after a fixed test clock.
func newTestServer(t *testing.T, opts ...Option) (*httptest.Server, sign.Signer, []byte) {
	t.Helper()
	seed, err := sign.GenerateSeed()
	if err != nil {
		t.Fatalf("GenerateSeed: %v", err)
	}
	signer, err := sign.NewSignerFromSeed(seed, "nl-fleet-2026")
	if err != nil {
		t.Fatalf("NewSignerFromSeed: %v", err)
	}
	blob, err := os.ReadFile(fixtureNL1)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	f := fleet.New(
		[]*fleet.Member{{Label: "nl-1", Priority: 10, ConfigJSON: blob}},
		fakeOracle{up: map[string]bool{"nl-1": true}},
		"priority", 0,
	)
	all := append([]Option{WithClock(func() time.Time { return time.Unix(1730900000, 0) })}, opts...)
	srv := NewServer(f, signer, all...)
	return httptest.NewServer(srv.Handler()), *signer, blob
}

// decoded is the minimal shape the client cares about (DESIGN.md §5.3).
type decoded struct {
	HostName   string `json:"hostName"`
	Containers []struct {
		Container string `json:"container"`
		Awg       struct {
			LastConfig string `json:"last_config"`
		} `json:"awg"`
	} `json:"containers"`
}

// TestAcceptance plays the proposed client end-to-end (DESIGN.md Appendix E):
// GET, verify signature, decode vpn://, parse JSON, assert the shape.
func TestAcceptance(t *testing.T) {
	ts, signer, _ := newTestServer(t)
	defer ts.Close()
	pinnedPub := signer.PublicKey()

	// 1. GET /v1/config; parse the envelope.
	env := getEnvelope(t, ts.URL+"/v1/config")
	if env.Alg != "ed25519" {
		t.Fatalf("alg = %q, want ed25519", env.Alg)
	}
	if env.Kid != "nl-fleet-2026" {
		t.Fatalf("kid = %q", env.Kid)
	}
	if env.Ts != 1730900000 {
		t.Fatalf("ts = %d", env.Ts)
	}

	// 2. Verify the signature over the exact config string.
	ok, err := sign.Verify(pinnedPub, env.Config, env.Sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("signature did not verify")
	}

	// 3. Strip vpn://, base64url-decode, qUncompress-or-raw, JSON-parse.
	raw, err := vpnblob.Decode(env.Config)
	if err != nil {
		t.Fatalf("vpnblob.Decode: %v", err)
	}
	var d decoded
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal decoded config: %v", err)
	}

	// 4. Assert the shape.
	if d.HostName == "" {
		t.Fatal("hostName empty")
	}
	if len(d.Containers) == 0 || d.Containers[0].Container != "amnezia-awg" {
		t.Fatalf("containers[0].container = %+v, want amnezia-awg", d.Containers)
	}
	var inner struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal([]byte(d.Containers[0].Awg.LastConfig), &inner); err != nil {
		t.Fatalf("last_config is not JSON: %v", err)
	}
	if !strings.Contains(inner.Config, "[Peer]") {
		t.Fatal("inner config missing [Peer]")
	}
	if !strings.Contains(inner.Config, "Endpoint = "+d.HostName) {
		t.Fatalf("inner [Peer] Endpoint does not match hostName %q", d.HostName)
	}
}

// TestAcceptance_TamperFails: flipping one byte of config breaks the signature.
func TestAcceptance_TamperFails(t *testing.T) {
	ts, signer, _ := newTestServer(t)
	defer ts.Close()

	env := getEnvelope(t, ts.URL+"/v1/config")
	tampered := []byte(env.Config)
	tampered[len(tampered)-1] ^= 0x01 // flip a bit in the last byte
	ok, err := sign.Verify(signer.PublicKey(), string(tampered), env.Sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("tampered config verified — signature is not binding")
	}
}

// TestAcceptance_WrongKeyFails: a different pinned key rejects a genuine config.
func TestAcceptance_WrongKeyFails(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	env := getEnvelope(t, ts.URL+"/v1/config")
	otherSeed, _ := sign.GenerateSeed()
	other, _ := sign.NewSignerFromSeed(otherSeed, "attacker")
	ok, err := sign.Verify(other.PublicKey(), env.Config, env.Sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("config verified under the wrong key")
	}
}

// TestPubkeyEndpoint: /v1/pubkey returns the pinned key, round-trippable.
func TestPubkeyEndpoint(t *testing.T) {
	ts, signer, _ := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/pubkey")
	if err != nil {
		t.Fatalf("GET pubkey: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	got := strings.TrimSpace(string(buf[:n]))

	pub, err := sign.ParsePublicKey(got)
	if err != nil {
		t.Fatalf("ParsePublicKey(%q): %v", got, err)
	}
	if !pub.Equal(signer.PublicKey()) {
		t.Fatal("served pubkey does not match signer")
	}
}

// TestEnvelopeWireKeys asserts the raw JSON body carries the exact wire keys a
// real client reads (interop invariant #6) and that the payload is unpadded
// URL-safe base64 (invariant #1) — decoding through the shared Envelope struct
// would hide a json-tag rename, so this inspects the bytes directly.
func TestEnvelopeWireKeys(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/config")
	if err != nil {
		t.Fatalf("GET config: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("body is not a JSON object: %v", err)
	}
	for _, k := range []string{"config", "sig", "alg", "kid", "ts"} {
		if _, ok := raw[k]; !ok {
			t.Fatalf("envelope missing required wire key %q; body=%s", k, body)
		}
	}

	var cfg string
	if err := json.Unmarshal(raw["config"], &cfg); err != nil {
		t.Fatalf("config is not a JSON string: %v", err)
	}
	if !strings.HasPrefix(cfg, vpnblob.Prefix) {
		t.Fatalf("config missing vpn:// prefix")
	}
	payload := strings.TrimPrefix(cfg, vpnblob.Prefix)
	if strings.ContainsAny(payload, "=+/") {
		t.Fatalf("payload is not RawURLEncoding (contains =, + or /): interop invariant #1")
	}

	var alg string
	_ = json.Unmarshal(raw["alg"], &alg)
	if alg != Alg {
		t.Fatalf("alg = %q, want %q", alg, Alg)
	}
	var tsVal int64
	if err := json.Unmarshal(raw["ts"], &tsVal); err != nil {
		t.Fatalf("ts is not an integer (unix seconds): %v", err)
	}
}

// TestAcceptance_Compressed runs the full client loop over the --compress path:
// the signature must cover the compressed config string and the qCompress frame
// must decode back to valid JSON.
func TestAcceptance_Compressed(t *testing.T) {
	ts, signer, _ := newTestServer(t, WithCompress(true))
	defer ts.Close()

	env := getEnvelope(t, ts.URL+"/v1/config")
	ok, err := sign.Verify(signer.PublicKey(), env.Config, env.Sig)
	if err != nil || !ok {
		t.Fatalf("compressed envelope signature: ok=%v err=%v", ok, err)
	}
	raw, err := vpnblob.Decode(env.Config)
	if err != nil {
		t.Fatalf("Decode compressed payload: %v", err)
	}
	var d decoded
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("compressed payload not JSON: %v", err)
	}
	if d.HostName == "" || len(d.Containers) == 0 || d.Containers[0].Container != "amnezia-awg" {
		t.Fatalf("compressed payload shape wrong: %+v", d)
	}
}

func getEnvelope(t *testing.T, url string) Envelope {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return env
}
