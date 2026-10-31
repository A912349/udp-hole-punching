package protocol

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestCompactRoundTripAndSizes(t *testing.T) {
	key := make([]byte, 32)
	src := strings.Repeat("a", 32)
	dst := strings.Repeat("b", 32)

	ping := NewPacket("PING", src, dst, map[string]any{})
	ping.Timestamp = time.Now().Unix()
	encoded, err := EncodeCompact(ping, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != CompactPingSize {
		t.Fatalf("compact PING size = %d, want %d", len(encoded), CompactPingSize)
	}
	decoded, err := DecodeCompact(encoded, key)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != "PING" || decoded.Source != src || decoded.Destination != dst ||
		decoded.ID != ping.ID || decoded.TTL != DefaultTTL || decoded.Timestamp != ping.Timestamp {
		t.Fatalf("round trip mismatch: %+v vs %+v", decoded, ping)
	}

	pong := NewPacket("PONG", dst, src, map[string]any{"ping_id": ping.ID})
	pong.Timestamp = time.Now().Unix()
	pongEncoded, err := EncodeCompact(pong, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(pongEncoded) != CompactPongSize {
		t.Fatalf("compact PONG size = %d, want %d", len(pongEncoded), CompactPongSize)
	}
	pongDecoded, err := DecodeCompact(pongEncoded, key)
	if err != nil {
		t.Fatal(err)
	}
	if pongDecoded.Type != "PONG" || pongDecoded.Payload["ping_id"] != ping.ID {
		t.Fatalf("PONG round trip mismatch: %+v", pongDecoded)
	}
}

func TestCompactHelloRoundTripAndSessionGuard(t *testing.T) {
	key := make([]byte, 32)
	src := strings.Repeat("a", 32)
	dst := strings.Repeat("b", 32)

	// A plain HELLO with the legacy public_key payload compacts to 70 bytes;
	// receivers ignore the payload, so dropping it is safe.
	hello := NewPacket("HELLO", src, dst, map[string]any{"public_key": "AQIDBAUGBw"})
	hello.Timestamp = time.Now().Unix()
	encoded, err := EncodeCompact(hello, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != CompactHelloSize {
		t.Fatalf("compact HELLO size = %d, want %d", len(encoded), CompactHelloSize)
	}
	decoded, err := DecodeCompact(encoded, key)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != "HELLO" || decoded.Source != src || decoded.Destination != dst ||
		decoded.ID != hello.ID || decoded.TTL != DefaultTTL || decoded.Timestamp != hello.Timestamp {
		t.Fatalf("HELLO round trip mismatch: %+v vs %+v", decoded, hello)
	}

	ack := NewPacket("HELLO_ACK", dst, src, map[string]any{"session_id": ""})
	ack.Timestamp = time.Now().Unix()
	ackEncoded, err := EncodeCompact(ack, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(ackEncoded) != CompactHelloAckSize {
		t.Fatalf("compact HELLO_ACK size = %d, want %d", len(ackEncoded), CompactHelloAckSize)
	}
	ackDecoded, err := DecodeCompact(ackEncoded, key)
	if err != nil {
		t.Fatal(err)
	}
	if ackDecoded.Type != "HELLO_ACK" || ackDecoded.Source != dst || ackDecoded.Destination != src {
		t.Fatalf("HELLO_ACK round trip mismatch: %+v", ackDecoded)
	}

	// A symmetric-scan HELLO echoes a session_id in HELLO_ACK, which the
	// compact format cannot carry: encoding must refuse instead of silently
	// dropping the field and stranding the scan handshake.
	scan := NewPacket("HELLO", src, dst, map[string]any{"public_key": "k", "session_id": "abcdef"})
	if _, err := EncodeCompact(scan, key); err == nil {
		t.Fatal("EncodeCompact accepted a session-carrying HELLO")
	}
	scanAck := NewPacket("HELLO_ACK", dst, src, map[string]any{"session_id": "abcdef"})
	if _, err := EncodeCompact(scanAck, key); err == nil {
		t.Fatal("EncodeCompact accepted a session-carrying HELLO_ACK")
	}
}

func TestCompactRejectsTampering(t *testing.T) {
	key := make([]byte, 32)
	other := make([]byte, 32)
	other[0] = 1
	src := strings.Repeat("a", 32)
	dst := strings.Repeat("b", 32)

	encoded, err := EncodeCompact(NewPacket("PING", src, dst, map[string]any{}), key)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong key must fail authentication.
	if _, err := DecodeCompact(encoded, other); err == nil {
		t.Fatal("DecodeCompact accepted a packet sealed with a different key")
	}
	// Any modified byte (header or MAC) must fail authentication.
	for i := 0; i < len(encoded); i += 7 {
		tampered := append([]byte(nil), encoded...)
		tampered[i] ^= 0x40
		if _, err := DecodeCompact(tampered, key); err == nil {
			t.Fatalf("DecodeCompact accepted tampered byte %d", i)
		}
	}
	// Truncation and padding must be rejected.
	if _, err := DecodeCompact(encoded[:len(encoded)-1], key); err == nil {
		t.Fatal("DecodeCompact accepted a truncated packet")
	}
	padded := append(append([]byte(nil), encoded...), 0)
	if _, err := DecodeCompact(padded, key); err == nil {
		t.Fatal("DecodeCompact accepted a padded packet")
	}
	// Unknown compact type must be rejected.
	unknown := append([]byte(nil), encoded...)
	unknown[1] = 9
	if _, err := DecodeCompact(unknown, key); err == nil {
		t.Fatal("DecodeCompact accepted an unknown compact type")
	}
	// JSON packets must not be classified as compact.
	jsonPacket, err := EncodePacket(NewPacket("PING", src, dst, map[string]any{}), key)
	if err != nil {
		t.Fatal(err)
	}
	if IsCompact(jsonPacket) {
		t.Fatal("IsCompact classified a JSON packet as compact")
	}
	if _, err := DecodeCompact(jsonPacket, key); err == nil {
		t.Fatal("DecodeCompact accepted a JSON packet")
	}
}

func TestCompactEncodeRejectsOtherTypes(t *testing.T) {
	key := make([]byte, 32)
	// HELLO/HELLO_ACK are compact-encodable since the capability-gated HELLO
	// change; DATA and unknown types must still be refused.
	if _, err := EncodeCompact(NewPacket("DATA", strings.Repeat("a", 32), strings.Repeat("b", 32), map[string]any{}), key); err == nil {
		t.Fatal("EncodeCompact accepted a DATA packet")
	}
	pong := NewPacket("PONG", strings.Repeat("a", 32), strings.Repeat("b", 32), map[string]any{})
	if _, err := EncodeCompact(pong, key); err == nil {
		t.Fatal("EncodeCompact accepted a PONG without ping_id")
	}
	// The magic byte must not collide with the fast-path prefix or JSON.
	if fastOrJSON := []byte{'{'}; IsCompact(fastOrJSON) {
		t.Fatal("IsCompact classified JSON as compact")
	}
	if bytes.Equal([]byte{compactMagic}, []byte("MIP1")[:1]) {
		t.Fatal("compact magic collides with the fast-path magic")
	}
}
