// Package sign implements fleetcore's Ed25519 signing (DESIGN.md Appendix D).
//
// The signature is the interop anchor: a client trusts an updated config only
// if it is signed by the public key it pinned at import time. Keep this file
// boring and exact — it is the authoritative definition the client verifier
// must match.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// PubKeyPrefix is the textual scheme fleetcore advertises public keys with.
// The full form is "ed25519:" + base64std(32-byte public key) — that string is
// what GET /v1/pubkey returns and what a client config pins as update_pubkey.
const PubKeyPrefix = "ed25519:"

// Signer holds a loaded private key plus its key id (kid), used to sign the
// envelope's config string.
type Signer struct {
	priv ed25519.PrivateKey
	Kid  string
}

// GenerateSeed returns a fresh 32-byte Ed25519 seed. keygen persists this.
func GenerateSeed() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv.Seed(), nil
}

// EncodeKeyFile renders a seed as the on-disk key-file body: base64std of the
// 32-byte seed on a single line. Written with mode 0600 (DESIGN.md D.1).
func EncodeKeyFile(seed []byte) string {
	return base64.StdEncoding.EncodeToString(seed) + "\n"
}

// LoadSigner reads a key file and returns a Signer. It accepts, in order:
//   - base64std text of a 32-byte seed or 64-byte private key (the format
//     EncodeKeyFile writes), possibly surrounded by whitespace;
//   - raw binary of exactly 32 (seed) or 64 (full private key) bytes.
func LoadSigner(keyFile, kid string) (*Signer, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	priv, err := parsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse key file %q: %w", keyFile, err)
	}
	return &Signer{priv: priv, Kid: kid}, nil
}

// NewSignerFromSeed builds a Signer directly from a 32-byte seed (used by tests
// and by keygen when it also needs to print the derived public key).
func NewSignerFromSeed(seed []byte, kid string) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return &Signer{priv: ed25519.NewKeyFromSeed(seed), Kid: kid}, nil
}

func parsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	// Try the text form first: base64std of a 32- or 64-byte key.
	if trimmed := strings.TrimSpace(string(raw)); trimmed != "" {
		if dec, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
			if k, ok := keyFromBytes(dec); ok {
				return k, nil
			}
		}
	}
	// Fall back to raw binary.
	if k, ok := keyFromBytes(raw); ok {
		return k, nil
	}
	return nil, errors.New("expected a 32-byte seed or 64-byte Ed25519 private key (raw or base64std)")
}

func keyFromBytes(b []byte) (ed25519.PrivateKey, bool) {
	switch len(b) {
	case ed25519.SeedSize: // 32
		return ed25519.NewKeyFromSeed(b), true
	case ed25519.PrivateKeySize: // 64
		return ed25519.PrivateKey(b), true
	default:
		return nil, false
	}
}

// SignConfig returns base64std(Ed25519_Sign(priv, utf8bytes(config))) — the
// exact "sig" value for the envelope. config MUST be the full envelope config
// string including the "vpn://" prefix (DESIGN.md D.2).
func (s *Signer) SignConfig(config string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, []byte(config)))
}

// PublicKey returns the 32-byte Ed25519 public key.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// PublicKeyString renders a public key as "ed25519:<base64std>".
func PublicKeyString(pub ed25519.PublicKey) string {
	return PubKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey inverts PublicKeyString: it accepts "ed25519:<base64std>" (the
// bare base64std form is also tolerated) and returns the key. Used by the
// client-stub acceptance test to load a pinned key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, PubKeyPrefix)
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(dec) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(dec))
	}
	return ed25519.PublicKey(dec), nil
}

// Verify checks a detached signature the way a client must: it decodes sig from
// base64std and verifies it over the raw bytes of config against pub.
func Verify(pub ed25519.PublicKey, config, sig string) (bool, error) {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(pub, []byte(config), raw), nil
}
