package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"testing"

	"home-udp-mesh/internal/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

// benchCompactDest is the 32-hex destination used by the compact envelope
// benchmarks below, whose packet ID comes from NewPacket instead.
const benchCompactDest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// BenchmarkHotPathCrypto measures the two per-packet crypto operations that
// dominate the data plane: the redundant network HMAC-SHA256 and the actual
// ChaCha20-Poly1305 seal, using a representative ~1280-byte payload.
func BenchmarkHotPathCrypto(b *testing.B) {
	key := make([]byte, 32)
	payload := make([]byte, 1279)
	aead, _ := chacha20poly1305.New(key)
	nonce := make([]byte, aead.NonceSize())
	dst := make([]byte, 0, len(payload)+aead.Overhead())
	mac := hmac.New(sha256.New, key)
	pool := []hash.Hash{mac}

	b.Run("HMAC-SHA256-per-packet", func(b *testing.B) {
		h := pool[0]
		out := make([]byte, 0, 32)
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			h.Reset()
			h.Write(payload)
			out = h.Sum(out[:0])
		}
	})

	b.Run("ChaCha20-Poly1305-Seal", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst = aead.Seal(dst[:0], nonce, payload, nil)
		}
	})

	b.Run("Both-as-today", func(b *testing.B) {
		h := pool[0]
		out := make([]byte, 0, 32)
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst = aead.Seal(dst[:0], nonce, payload, nil)
			h.Reset()
			h.Write(dst)
			out = h.Sum(out[:0])
		}
		})
}

// BenchmarkCompactEnvelopeFresh measures one keepalive frame's encode/decode
// pair when every codec call builds its own HMAC state for the network key,
// which is what the standalone codecs do and what a node does when it has
// nowhere to keep one.
func BenchmarkCompactEnvelopeFresh(b *testing.B) {
	key := make([]byte, 32)
	ping := protocol.NewPacket("PING", benchCompactDest, benchCompactDest, map[string]any{})
	var sink int
	for i := range b.N {
		ping.Timestamp = 1000 + int64(i)
		buf, e := protocol.EncodeCompact(ping, key)
		if e != nil {
			panic(e)
		}
		packet, e := protocol.DecodeCompact(buf, key)
		if e != nil {
			panic(e)
		}
		sink += len(packet.Type) + len(buf)
	}
	if sink == 0 {
		panic("sink")
	}
}

// BenchmarkCompactEnvelopePooled measures the same pair through the reusable
// states a node holds: the state rebuilds its key schedule once and rewinds
// it on Reset instead of building a state per frame.
func BenchmarkCompactEnvelopePooled(b *testing.B) {
	key := make([]byte, 32)
	holder := protocol.NewPooledMAC(key)
	ping := protocol.NewPacket("PING", benchCompactDest, benchCompactDest, map[string]any{})
	var sink int
	for i := range b.N {
		ping.Timestamp = 1000 + int64(i)
		buf, e := protocol.EncodeCompactReuse(ping, holder)
		if e != nil {
			panic(e)
		}
		packet, e := protocol.DecodeCompactReuse(buf, holder)
		if e != nil {
			panic(e)
		}
		sink += len(packet.Type) + len(buf)
	}
	if sink == 0 {
		panic("sink")
	}
}
