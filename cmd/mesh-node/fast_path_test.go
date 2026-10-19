package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"home-udp-mesh/internal/protocol"
)

func TestRememberFastRejectsDuplicatesAndEvictsOldest(t *testing.T) {
	n := &node{
		fastSeen:     make(map[[12]byte]struct{}, fastSeenCapacity),
		fastSeenRing: make([][12]byte, 0, fastSeenCapacity),
	}
	var first [12]byte
	if !n.rememberFast(first) || n.rememberFast(first) {
		t.Fatal("fast duplicate detection did not reject a duplicate")
	}
	for value := uint64(1); value <= fastSeenCapacity; value++ {
		var id [12]byte
		binary.BigEndian.PutUint64(id[4:], value)
		if !n.rememberFast(id) {
			t.Fatalf("new packet ID %d was rejected", value)
		}
	}
	if !n.rememberFast(first) {
		t.Fatal("oldest packet ID was not evicted")
	}
}

func TestFastFrameInPlaceSealLayout(t *testing.T) {
	aead, err := protocol.NewAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := protocol.NewNonceSequence()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("fragment header and an IP packet")
	plainAt := fastHeader + aead.NonceSize()
	sealedEnd := plainAt + len(plain) + aead.Overhead()
	frame := make([]byte, plainAt+len(plain), sealedEnd)
	copy(frame[plainAt:], plain)
	if err := sequence.NextInto(frame[fastHeader:plainAt]); err != nil {
		t.Fatal(err)
	}
	frame = aead.Seal(frame[:plainAt], frame[fastHeader:plainAt], frame[plainAt:], nil)
	opened, err := protocol.OpenBytesWithAEAD(aead, frame[fastHeader:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatalf("opened %q, want %q", opened, plain)
	}
}

func TestNextPacketIDUsesPrefixAndMonotonicCounter(t *testing.T) {
	n := &node{packetPrefix: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	var first, second [12]byte
	if !n.nextPacketID(first[:]) || !n.nextPacketID(second[:]) {
		t.Fatal("packet ID sequence failed")
	}
	if !bytes.Equal(first[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("unexpected packet prefix: %x", first[:8])
	}
	if got := binary.BigEndian.Uint32(first[8:]); got != 1 {
		t.Fatalf("first counter = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint32(second[8:]); got != 2 {
		t.Fatalf("second counter = %d, want 2", got)
	}
	n.packetCounter.Store(^uint32(0))
	if n.nextPacketID(first[:]) {
		t.Fatal("exhausted packet ID sequence was accepted")
	}
}

// The header packet ID doubles as the AEAD nonce, so a frame replayed with a
// forged header ID (bypassing dedupe) must fail decryption exactly like a
// frame whose bytes were tampered with.
func TestFastFrameRejectsForgedPacketID(t *testing.T) {
	aead, err := protocol.NewAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("fragment header and an IP packet")
	seal := func(packetID [12]byte) []byte {
		sealedAt := fastHeader + len(packetID)
		frame := make([]byte, sealedAt+len(plain), sealedAt+len(plain)+aead.Overhead())
		copy(frame[37:49], packetID[:])       // header packet ID field
		copy(frame[fastHeader:], packetID[:]) // nonce region: same bytes
		copy(frame[sealedAt:], plain)
		return aead.Seal(frame[:sealedAt], frame[fastHeader:sealedAt], frame[sealedAt:], nil)
	}
	var realID [12]byte
	if _, err := rand.Read(realID[:]); err != nil {
		t.Fatal(err)
	}
	frame := seal(realID)
	// Receiver path: open with the header ID as nonce.
	var headerID [12]byte
	copy(headerID[:], frame[37:49])
	if _, err := aead.Open(nil, headerID[:], frame[fastHeader+aead.NonceSize():], nil); err != nil {
		t.Fatalf("legitimate frame failed to open: %v", err)
	}
	// Replay forgery: fresh header ID to bypass dedupe, sealed bytes untouched.
	var forgedID [12]byte
	if _, err := rand.Read(forgedID[:]); err != nil {
		t.Fatal(err)
	}
	copy(frame[37:49], forgedID[:])
	if _, err := aead.Open(nil, forgedID[:], frame[fastHeader+aead.NonceSize():], nil); err == nil {
		t.Fatal("forged packet ID was accepted; replay protection is broken")
	}
}
