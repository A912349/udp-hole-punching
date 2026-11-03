package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

// Exercise the real sender, UDP framing, authentication and receiver together.
func TestFastAuthentication(t *testing.T) {
	idA, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idB, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	connA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()
	a := newBenchNode(idA, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), connA)
	b := newBenchNode(idB, &benchTUN{}, netip.MustParseAddr("10.77.0.6"), connB)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wireNodes(ctx, a, b, connA.LocalAddr().(*net.UDPAddr), connB.LocalAddr().(*net.UDPAddr))
	packet := make([]byte, maxTUN)
	packet[0] = 0x45
	copy(packet[12:16], []byte{10, 77, 0, 5})
	copy(packet[16:20], []byte{10, 77, 0, 6})
	if !a.sendIP(idB.ID, packet) {
		t.Fatal("send failed")
	}
	connB.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65536)
	size, addr, err := connB.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte(nil), buf[:size]...)
	if size != maxFastFrame {
		t.Fatalf("frame size = %d, want %d", size, maxFastFrame)
	}
	// Immutable peer/packet IDs, nonce, ciphertext and tag are protected.
	// TTL is deliberately mutable and is not end-to-end authenticated.
	for _, offset := range []int{5, 21, 37, fastHeader, fastHeader + 12, size - 1} {
		forged := append([]byte(nil), frame...)
		forged[offset] ^= 1
		b.fast(forged, addr)
		if b.fastSeenCount() != 0 {
			t.Fatalf("tampering at %d poisoned duplicate cache", offset)
		}
	}
	// A captured frame with a fresh ID must not poison duplicate state.
	forged := append([]byte(nil), frame...)
	binary.BigEndian.PutUint64(forged[41:49], 999)
	b.fast(forged, addr)
	if b.fastSeenCount() != 0 {
		t.Fatal("invalid end-to-end tag poisoned duplicate cache")
	}
	b.fast(append([]byte(nil), frame...), addr)
	if b.fastSeenCount() != 1 {
		t.Fatal("valid sender frame rejected")
	}
	b.fast(append([]byte(nil), frame...), addr)
	b.fast(forged, addr) // replay the captured ciphertext under a different ID
	if b.fastSeenCount() != 1 {
		t.Fatal("duplicate or forged replay changed cache")
	}
	deadline := time.Now().Add(time.Second)
	for b.stats.deliveredPackets.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := b.stats.deliveredPackets.Load(); got != 1 {
		t.Fatalf("delivered = %d, want 1", got)
	}
}

// TestPeerCryptoDerivesOnCacheMiss verifies the single-lock peerCrypto path
// derives and caches the symmetric AEAD on a cache miss, and that the returned
// AEAD can seal and open an authenticated frame. This is the path peerKey
// uses for peerAEAD/peerCipher when a peer's key isn't cached yet.
func TestPeerCryptoDerivesOnCacheMiss(t *testing.T) {
	idA, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idB, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := newBenchNode(idA, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), nil)
	dir := &peer{ID: idB.ID, Public: idB.Public}
	n.dir[idB.ID] = dir

	// Cold cache: no shared key yet, so peerCrypto must derive it once, under a
	// single read lock plus a write lock on the miss.
	cached, _, e := n.peerCrypto(idB.ID)
	if e != nil {
		t.Fatalf("peerCrypto cache-miss derivation failed: %v", e)
	}
	if cached.aead == nil || cached.key == nil || cached.nonces == nil {
		t.Fatal("peerCrypto miss did not derive AEAD/key/nonces")
	}
	// A subsequent lookup must hit the cache and return the same AEAD.
	cached2, _, e2 := n.peerCrypto(idB.ID)
	if e2 != nil {
		t.Fatalf("peerCrypto cache hit failed: %v", e2)
	}
	if cached2.aead != cached.aead {
		t.Fatal("peerCrypto did not reuse the derived AEAD")
	}
	// The derived AEAD must seal and open a frame. For a single node its own
	// seal direction uses sealAAD consistently; across nodes a sender's sealAAD
	// equals the receiver's openAAD, so the two cached AADs are complementary.
	plaintext := []byte("authenticated fast frame")
	sealed, err := protocol.SealBytesWithSequence(cached.aead, cached.nonces, plaintext, cached.sealAAD)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	opened, err := protocol.OpenBytesWithAEAD(cached.aead, sealed, cached.sealAAD)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("open != plaintext: %q", opened)
	}
	// A single flipped byte in the tag must be rejected.
	sealed[len(sealed)-1] ^= 0x01
	if _, err := protocol.OpenBytesWithAEAD(cached.aead, sealed, cached.sealAAD); err == nil {
		t.Fatal("tampered frame was accepted")
	}
}
