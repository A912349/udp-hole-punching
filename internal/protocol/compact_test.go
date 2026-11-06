package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
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

// One PooledMAC reused over consecutive frames must keep producing the tags a
// freshly built state produces. A state that failed to rewind would leak the
// previous frame into the next tag.
func TestCompactMACReuseAcrossFrames(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	src := strings.Repeat("a", 32)
	dst := strings.Repeat("b", 32)
	ping := NewPacket("PING", src, dst, map[string]any{})
	ping.Timestamp = 1000
	held, err := EncodeCompact(ping, key)
	if err != nil {
		t.Fatal("EncodeCompact: ", err)
	}
	var reused *PooledMAC
	reused = NewPooledMAC(key)
	first, err := EncodeCompactReuse(ping, reused)
	if err != nil {
		t.Fatal("EncodeCompactReuse: ", err)
	}
	if !bytes.Equal(first, held) {
		t.Fatal("a reused state disagrees with a fresh one on the same frame")
	}
	next := NewPacket("PING", strings.Repeat("c", 32), strings.Repeat("d", 32), map[string]any{})
	next.Timestamp = 2000
	expected, err := EncodeCompact(next, key)
	if err != nil {
		t.Fatal("EncodeCompact: ", err)
	}
	actual, err := EncodeCompactReuse(next, reused)
	if err != nil {
		t.Fatal("EncodeCompactReuse: ", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("reusing the state leaked the earlier frame into the next tag")
	}
	if bytes.Equal(actual, first) {
		t.Fatal("the second frame repeated the first frame's tag")
	}
	// Decoding through the same holder sees the keyed state, not leftovers.
	decoded, err := DecodeCompactReuse(first, reused)
	if err != nil {
		t.Fatal("DecodeCompactReuse: ", err)
	}
	if decoded.Type != "PING" || decoded.Source != src || decoded.Destination != dst {
		t.Fatal("DecodeCompactReuse restored the wrong packet")
	}
}

// TestJSONEnvelopeMacPairPosition locks the provider wire format across mesh
// versions. The MAC covers the canonical envelope without the mac key, so the
// pair may sit anywhere in the emitted object: EncodePacket appends it after the
// authenticated bytes, while a sender predating that splice inserted it into the
// map and canonicalised the whole envelope, landing the pair in sorted position.
// Both forms must verify, must carry one and the same tag, and must survive an
// envelope whose payload needs JSON escaping.
func TestJSONEnvelopeMacPairPosition(t *testing.T) {
	key := make([]byte, 32)
	src := strings.Repeat("a", 32)
	dst := strings.Repeat("b", 32)
	body := map[string]any{"note": "a \"quote\" and ünï", "nested": map[string]any{"k": 1}}
	p := NewPacket("PING", src, dst, body)
	p.Timestamp = time.Now().Unix()

	// The authenticated bytes are the canonical envelope without the mac key,
	// computed with a state of its own so the expected tag is independent of
	// whichever encoder produced the wire.
	canonical, err := CanonicalJSON(p.envelope())
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	want := B64Encode(mac.Sum(nil))

	appended, err := EncodePacket(p, key)
	if err != nil {
		t.Fatal(err)
	}
	// The old shape: the pair inserted into the map, then canonicalised whole.
	legacy := p.envelope()
	legacy["mac"] = want
	sorted, err := CanonicalJSON(legacy)
	if err != nil {
		t.Fatal(err)
	}

	check := func(label string, wire []byte) {
		decoded, e := DecodePacket(wire, key)
		if e != nil {
			t.Fatalf("%s wire rejected: %v", label, e)
		}
		if decoded.Type != "PING" || decoded.Source != src || decoded.Destination != dst ||
			decoded.ID != p.ID || decoded.Timestamp != p.Timestamp {
			t.Fatalf("%s envelope fields lost: %+v", label, decoded)
		}
		if note, _ := decoded.Payload["note"].(string); note != "a \"quote\" and ünï" {
			t.Fatalf("%s payload note mangled: %s", label, note)
		}
		var parsed map[string]any
		if err2 := json.Unmarshal(wire, &parsed); err2 != nil {
			t.Fatalf("%s wire unparsable: %v", label, err2)
		}
		tag, _ := parsed["mac"].(string)
		if tag != want {
			t.Fatalf("%s tag differs from the canonical envelope's MAC", label)
		}
	}
	check("appended", appended)
	check("sorted", sorted)
}
