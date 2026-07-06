// Package vpnblob encodes an Amnezia config JSON into the "vpn://…" string the
// client applies, and decodes it back (for the acceptance test / a client stub).
//
// It is the exact inverse of the client decode contract in DESIGN.md Appendix A,
// verified against amnezia-client fillServerConfig at tag 4.8.19.0:
//
//	strip "vpn://"  ->  base64url(no pad) decode  ->  qUncompress-or-raw  ->  JSON
//
// fleetcore emits EITHER plain JSON (MVP, Encode) OR Qt qCompress-framed JSON
// (EncodeCompressed). It must never emit bare zlib/gzip: those neither match Qt
// framing nor survive the client's decompress-fallback (Appendix A step 6).
package vpnblob

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// Prefix is the scheme prepended to the base64url payload.
const Prefix = "vpn://"

// maxDecompressed bounds qUncompress output to avoid a decompression bomb from a
// hostile blob. fleetcore only ever decodes its own output (tests), but the
// client-stub path should still be defensive.
const maxDecompressed = 32 << 20 // 32 MiB

// Encode wraps raw Amnezia config JSON into a vpn:// string using
// base64.RawURLEncoding (URL alphabet, no padding) — matching the client's
// Base64UrlEncoding | OmitTrailingEquals decode (DESIGN.md D.3). MVP path.
func Encode(raw []byte) string {
	return Prefix + base64.RawURLEncoding.EncodeToString(raw)
}

// EncodeCompressed applies Qt qCompress framing before base64:
//
//	[4-byte big-endian uint32 = len(raw)] || zlib.Deflate(raw)
//
// The 4-byte prefix MUST be the ACTUAL uncompressed size; a wrong value makes
// the client's qUncompress fail and silently fall back to the still-compressed
// bytes, yielding an empty JSON object (DESIGN.md D.4).
func EncodeCompressed(raw []byte) (string, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(raw))); err != nil {
		return "", err
	}
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// Decode inverts Encode/EncodeCompressed the way the client does, so the
// acceptance test can prove round-trips. It:
//
//  1. removes ALL "vpn://" occurrences (client uses QString::replace, which is
//     global — this is why "vpn://" must appear only as the prefix);
//  2. base64url-decodes, tolerating stray padding;
//  3. errors on an empty decode (Appendix A step 4);
//  4. tries qUncompress; if the bytes are not valid Qt qCompress framing, keeps
//     the raw decoded bytes (the load-bearing fallback, Appendix A step 6).
func Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, Prefix, "")
	// RawURLEncoding rejects '=' padding; the client's decode is padding
	// tolerant, so mirror that by trimming any trailing '=' first.
	s = strings.TrimRight(s, "=")
	dec, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(dec) == 0 {
		return nil, errors.New("empty payload")
	}
	if un, ok := qUncompress(dec); ok {
		return un, nil
	}
	return dec, nil
}

// qUncompress mimics Qt's qUncompress: it expects a 4-byte big-endian
// uncompressed-size prefix followed by a zlib stream, and returns ok=false
// (rather than an error) for anything that is not that exact framing, so the
// caller can fall back to the raw bytes.
func qUncompress(b []byte) ([]byte, bool) {
	if len(b) < 4 {
		return nil, false
	}
	size := binary.BigEndian.Uint32(b[:4])
	if size == 0 || size > maxDecompressed {
		return nil, false
	}
	zr, err := zlib.NewReader(bytes.NewReader(b[4:]))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxDecompressed+1))
	if err != nil {
		return nil, false
	}
	if uint32(len(out)) != size {
		return nil, false
	}
	return out, true
}
