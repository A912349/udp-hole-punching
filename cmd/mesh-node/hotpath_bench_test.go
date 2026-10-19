package main

// These tests cover hotpath bench behavior and regression cases.
import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

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
