package sign

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func newSigner(t *testing.T) *Signer {
	t.Helper()
	seed, err := GenerateSeed()
	if err != nil {
		t.Fatalf("GenerateSeed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed len = %d, want %d", len(seed), ed25519.SeedSize)
	}
	s, err := NewSignerFromSeed(seed, "test-kid")
	if err != nil {
		t.Fatalf("NewSignerFromSeed: %v", err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := newSigner(t)
	cfg := "vpn://abc123"
	sig := s.SignConfig(cfg)

	ok, err := Verify(s.PublicKey(), cfg, sig)
	if err != nil || !ok {
		t.Fatalf("Verify legit sig: ok=%v err=%v", ok, err)
	}
	ok, _ = Verify(s.PublicKey(), cfg+"x", sig)
	if ok {
		t.Fatal("verified over tampered config")
	}
}

func TestPublicKeyStringRoundTrip(t *testing.T) {
	s := newSigner(t)
	str := PublicKeyString(s.PublicKey())
	if str[:len(PubKeyPrefix)] != PubKeyPrefix {
		t.Fatalf("missing prefix: %q", str)
	}
	pub, err := ParsePublicKey(str)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !pub.Equal(s.PublicKey()) {
		t.Fatal("round-trip pubkey mismatch")
	}
}

// A key written by EncodeKeyFile must load and sign identically.
func TestLoadSignerFromFile(t *testing.T) {
	seed, _ := GenerateSeed()
	path := filepath.Join(t.TempDir(), "ed25519.key")
	if err := os.WriteFile(path, []byte(EncodeKeyFile(seed)), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSigner(path, "kid")
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	fromSeed, _ := NewSignerFromSeed(seed, "kid")

	cfg := "vpn://payload"
	if loaded.SignConfig(cfg) != fromSeed.SignConfig(cfg) {
		t.Fatal("loaded key signs differently from its seed")
	}
}

// Both a 32-byte seed and a 64-byte private key are accepted.
func TestParsePrivateKeyForms(t *testing.T) {
	seed, _ := GenerateSeed()
	priv := ed25519.NewKeyFromSeed(seed)
	for name, raw := range map[string][]byte{
		"seed32":    seed,
		"private64": priv,
	} {
		if _, err := parsePrivateKey(raw); err != nil {
			t.Errorf("%s (raw): %v", name, err)
		}
	}
	if _, err := parsePrivateKey([]byte("too short")); err == nil {
		t.Error("expected error for bad key bytes")
	}
}
