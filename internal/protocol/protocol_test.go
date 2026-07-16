package protocol

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"testing"
)

func TestPacketRoundTripAndAuthentication(t *testing.T) {
	key := sha256.Sum256([]byte("mesh test key"))
	packet := NewPacket("DATA", "source", "destination", map[string]any{"value": "hello"})
	encoded, err := EncodePacket(packet, key[:])
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePacket(encoded, key[:])
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ID != packet.ID || decoded.Source != packet.Source || decoded.Destination != packet.Destination {
		t.Fatalf("packet changed during round trip: %#v", decoded)
	}
	encoded[len(encoded)-2] ^= 1
	if _, err = DecodePacket(encoded, key[:]); err == nil {
		t.Fatal("tampered packet was accepted")
	}
}

func TestSealedPayloadRoundTrip(t *testing.T) {
	left, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	leftKey, err := SharedKey(left.Private, right.Public)
	if err != nil {
		t.Fatal(err)
	}
	rightKey, err := SharedKey(right.Private, left.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftKey, rightKey) {
		t.Fatal("X25519 key agreement differs by direction")
	}
	plain := []byte("end-to-end payload")
	aad := []byte(left.ID + ":" + right.ID)
	sealed, err := Seal(leftKey, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(rightKey, sealed, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatalf("got %q, want %q", opened, plain)
	}
	fastFrame, err := SealBytes(leftKey, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	fastOpened, err := OpenBytes(rightKey, fastFrame, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fastOpened, plain) {
		t.Fatalf("fast frame got %q, want %q", fastOpened, plain)
	}
	sequence, err := NewNonceSequence()
	if err != nil {
		t.Fatal(err)
	}
	first, err := SealBytesWithSequence(mustAEAD(t, leftKey), sequence, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SealBytesWithSequence(mustAEAD(t, leftKey), sequence, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[:12], second[:12]) {
		t.Fatal("nonce sequence reused a nonce")
	}
}

func mustAEAD(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	aead, err := NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}
