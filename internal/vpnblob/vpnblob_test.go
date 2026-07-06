package vpnblob

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	raw := []byte(`{"hostName":"203.0.113.10","containers":[]}`)
	s := Encode(raw)
	if !strings.HasPrefix(s, Prefix) {
		t.Fatalf("missing vpn:// prefix: %q", s)
	}
	// Payload must be RawURLEncoding: no '=' padding, URL alphabet only.
	payload := strings.TrimPrefix(s, Prefix)
	if strings.ContainsAny(payload, "=+/") {
		t.Fatalf("payload uses padded/std alphabet: %q", payload)
	}
	got, err := Decode(s)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("round-trip mismatch:\n got %s\nwant %s", got, raw)
	}
}

func TestEncodeMatchesRawURLEncoding(t *testing.T) {
	raw := []byte("hello, fleet")
	want := Prefix + base64.RawURLEncoding.EncodeToString(raw)
	if got := Encode(raw); got != want {
		t.Fatalf("Encode = %q, want %q", got, want)
	}
}

func TestCompressedRoundTrip(t *testing.T) {
	raw := []byte(strings.Repeat(`{"k":"v"}`, 100))
	s, err := EncodeCompressed(raw)
	if err != nil {
		t.Fatalf("EncodeCompressed: %v", err)
	}
	got, err := Decode(s)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatal("compressed round-trip mismatch")
	}
}

// TestCompressedFrameLayout pins the Qt qCompress wire framing directly (4-byte
// big-endian ACTUAL length prefix + a zlib stream) rather than round-tripping
// through our own qUncompress — a symmetric endianness swap would pass the round
// trip but break Qt's real qUncompress (DESIGN.md D.4, interop invariant #4).
func TestCompressedFrameLayout(t *testing.T) {
	raw := []byte(`{"hostName":"203.0.113.10"}`)
	s, err := EncodeCompressed(raw)
	if err != nil {
		t.Fatalf("EncodeCompressed: %v", err)
	}
	frame, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, Prefix))
	if err != nil {
		t.Fatalf("payload not RawURLEncoding: %v", err)
	}
	if len(frame) < 4 {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	if got := binary.BigEndian.Uint32(frame[:4]); got != uint32(len(raw)) {
		t.Fatalf("size prefix = %d (big-endian), want actual uncompressed len %d", got, len(raw))
	}
	zr, err := zlib.NewReader(bytes.NewReader(frame[4:]))
	if err != nil {
		t.Fatalf("bytes after prefix are not a zlib stream: %v", err)
	}
	defer zr.Close()
	inflated, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	if string(inflated) != string(raw) {
		t.Fatalf("inflated = %q, want %q", inflated, raw)
	}
}

// Plain JSON must survive the qUncompress fallback unchanged (Appendix A step 6).
func TestPlainJSONFallsBackToRaw(t *testing.T) {
	raw := []byte(`{"plain":"json"}`)
	got, err := Decode(Encode(raw))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("fallback mismatch: %s", got)
	}
}

func TestDecodeStripsAllPrefixes(t *testing.T) {
	// The client uses a global replace; ensure Decode mirrors that.
	raw := []byte("payload")
	s := Encode(raw)
	got, err := Decode(Prefix + s) // doubled prefix
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("got %s", got)
	}
}

func TestDecodeEmptyErrors(t *testing.T) {
	if _, err := Decode(Prefix); err == nil {
		t.Fatal("expected error on empty payload")
	}
}
