package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"home-udp-mesh/internal/protocol"
)

func TestRememberFastRejectsDuplicatesAndEvictsOldest(t *testing.T) {
	// The dedup ring is sharded by packetID; rememberFast lazily allocates the
	// shard's set, so a zero-value node is safe without eager init here.
	n := &node{}
	var first [12]byte
	if !n.rememberFast(first) || n.rememberFast(first) {
		t.Fatal("fast duplicate detection did not reject a duplicate")
	}
	// Overflow first's shard ring so its oldest entry (first) is evicted. A
	// duplicate is always routed to the same shard, so dedup stays exact even
	// though the per-shard window is smaller than the old single global ring.
	target := fastShard(first)
	inserted := 0
	for value := uint64(1); inserted < fastSeenRingCap; value++ {
		var id [12]byte
		binary.BigEndian.PutUint64(id[4:], value)
		if fastShard(id) == target && n.rememberFast(id) {
			inserted++
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
	n := &node{packetPrefix: [4]byte{1, 2, 3, 4}}
	var first, second [12]byte
	if !n.nextPacketID(first[:]) || !n.nextPacketID(second[:]) {
		t.Fatal("packet ID sequence failed")
	}
	if first[0] != 1 || first[1] != 2 || first[2] != 3 || first[3] != 4 {
		t.Fatalf("unexpected packet prefix: %x", first[:4])
	}
	if got := binary.BigEndian.Uint64(first[4:]); got != 1 {
		t.Fatalf("first counter = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint64(second[4:]); got != 2 {
		t.Fatalf("second counter = %d, want 2", got)
	}
	n.packetCounter.Store(^uint64(0))
	if n.nextPacketID(first[:]) {
		t.Fatal("exhausted packet ID sequence was accepted")
	}
}
