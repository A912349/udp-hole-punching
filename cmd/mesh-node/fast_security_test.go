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

// TestFastPeerAESnapshotSwitchesBetweenPeers locks the single-entry cipher
// snapshot: it must serve the same peer across datagrams, must not leak that
// peer's cipher to a different peer, and must not be replaced when the looked-up
// hex names no known peer.
func TestFastPeerAESnapshotSwitchesBetweenPeers(t *testing.T) {
	idA, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idB, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idC, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := newBenchNode(idA, &benchTUN{}, netip.MustParseAddr("10.77.0.6"), nil)
	n.dir[idB.ID] = &peer{ID: idB.ID, Public: idB.Public}
	n.dir[idC.ID] = &peer{ID: idC.ID, Public: idC.Public}

	derivedB, _, e := n.peerCrypto(idB.ID)
	if e != nil {
		t.Fatalf("peerCrypto for peer B failed: %v", e)
	}
	derivedC, _, e := n.peerCrypto(idC.ID)
	if e != nil {
		t.Fatalf("peerCrypto for peer C failed: %v", e)
	}

	var hexB [32]byte
	copy(hexB[:], []byte(idB.ID))
	var hexC [32]byte
	copy(hexC[:], []byte(idC.ID))

	// First lookup misses the snapshot and publishes it; the cipher must be the
	// one the shared-key cache already derived, not a freshly derived one.
	aead, aad, hex, e := n.fastPeerAEAD(hexB)
	if e != nil || aead != derivedB.aead || hex != idB.ID {
		t.Fatalf("snapshot miss returned the wrong cipher or ID: %v", e)
	}
	if !bytes.Equal(aad, derivedB.openAAD) {
		t.Fatalf("snapshot miss returned the wrong open AAD: %q", aad)
	}

	// The next datagram of the same burst hits the snapshot. The returned ID
	// string is the interned one, which is what the receive path needs without
	// allocating a hex string per datagram.
	second, aad2, hex2, e := n.fastPeerAEAD(hexB)
	if e != nil || second != derivedB.aead || hex2 != idB.ID {
		t.Fatalf("snapshot hit returned the wrong cipher or ID: %v", e)
	}
	if !bytes.Equal(aad2, derivedB.openAAD) {
		t.Fatalf("snapshot hit returned the wrong open AAD: %q", aad2)
	}

	// A different peer must not be served peer B's snapshot, and it must
	// republish so a later burst for B sees B again rather than a stale entry.
	peerC, aadC, hexCOut, e := n.fastPeerAEAD(hexC)
	if e != nil || peerC != derivedC.aead || hexCOut != idC.ID {
		t.Fatalf("snapshot leaked peer B's cipher to peer C: %v", e)
	}
	if !bytes.Equal(aadC, derivedC.openAAD) {
		t.Fatalf("peer C open AAD mismatch: %q", aadC)
	}
	backB, _, hexBack, e := n.fastPeerAEAD(hexB)
	if e != nil || backB != derivedB.aead || hexBack != idB.ID {
		t.Fatalf("snapshot did not switch back to peer B: %v", e)
	}

	// Unknown hex of the right shape must error and leave the last snapshot
	// alone, so a bogus burst cannot poison the cache.
	var bogus [32]byte
	copy(bogus[:], []byte("ffffffffffffffffffffffffffffffff"))
	if _, _, hexBogus, e := n.fastPeerAEAD(bogus); e == nil || hexBogus != "" {
		t.Fatal("unknown peer hex was accepted by the snapshot path")
	}
	reseenB, _, hexRe, e := n.fastPeerAEAD(hexB)
	if e != nil || reseenB != derivedB.aead || hexRe != idB.ID {
		t.Fatalf("poisoned snapshot served the wrong peer: %v", e)
	}
}
