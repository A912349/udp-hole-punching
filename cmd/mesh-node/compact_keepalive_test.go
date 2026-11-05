package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

// A compact PING must be answered with a compact PONG, and a JSON PING with a
// JSON PONG, so mixed-version fleets keep working during rolling upgrades.
func TestKeepaliveRepliesInKind(t *testing.T) {
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
	addrB := connB.LocalAddr().(*net.UDPAddr)

	a := newBenchNode(idA, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), connA)
	b := newBenchNode(idB, &benchTUN{}, netip.MustParseAddr("10.77.0.6"), connB)
	for _, n := range []*node{a, b} {
		n.seen = map[string]struct{}{}
		n.pings = map[string]pingProbe{}
	}
	a.neighbors[idB.ID] = &peer{ID: idB.ID, Endpoint: addrB.String()}
	buffer := make([]byte, 4096)

	// pingAll sends a compact PING to the neighbor.
	a.pingAll()
	connB.SetReadDeadline(time.Now().Add(time.Second))
	size, from, err := connB.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.IsCompact(buffer[:size]) {
		t.Fatalf("pingAll sent %d bytes that are not compact-encoded", size)
	}
	ping, err := protocol.DecodeCompact(buffer[:size], a.key)
	if err != nil || ping.Type != "PING" || ping.Source != idA.ID || ping.Destination != idB.ID {
		t.Fatalf("compact PING decode=%v packet=%+v", err, ping)
	}

	// The receiving node answers with a compact PONG echoing the probe ID.
	b.handleDatagram(append([]byte(nil), buffer[:size]...), from)
	connA.SetReadDeadline(time.Now().Add(time.Second))
	size, _, err = connA.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.IsCompact(buffer[:size]) {
		t.Fatalf("reply to a compact PING is not compact-encoded (%d bytes)", size)
	}
	pong, err := protocol.DecodeCompact(buffer[:size], b.key)
	if err != nil || pong.Type != "PONG" || pong.Payload["ping_id"] != ping.ID {
		t.Fatalf("compact PONG decode=%v packet=%+v want ping_id=%s", err, pong, ping.ID)
	}
	if pong.Source != idB.ID || pong.Destination != idA.ID {
		t.Fatalf("compact PONG addresses mismatch: %+v", pong)
	}

	// A legacy JSON PING still works and is answered in JSON.
	jsonPing := protocol.NewPacket("PING", idB.ID, idA.ID, map[string]any{})
	jsonEncoded, err := protocol.EncodePacket(jsonPing, b.key)
	if err != nil {
		t.Fatal(err)
	}
	a.handleDatagram(jsonEncoded, addrB)
	connB.SetReadDeadline(time.Now().Add(time.Second))
	size, _, err = connB.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.IsCompact(buffer[:size]) || buffer[0] != '{' {
		t.Fatalf("reply to a JSON PING must be JSON, got %d bytes starting %x", size, buffer[:2])
	}
	legacyPong, err := protocol.DecodePacket(buffer[:size], a.key)
	if err != nil || legacyPong.Type != "PONG" || legacyPong.Payload["ping_id"] != jsonPing.ID {
		t.Fatalf("JSON PONG decode=%v packet=%+v want ping_id=%s", err, legacyPong, jsonPing.ID)
	}
}

// HELLO/HELLO_ACK must stay JSON toward peers that have not demonstrated
// compact support (pre-compact versions), switch to the ~70-byte compact
// format once the peer proves it, and refuse to carry a symmetric-scan
// session_id, whose HELLO_ACK echo the compact format cannot represent.
func TestHelloCompactCapability(t *testing.T) {
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
	addrA := connA.LocalAddr().(*net.UDPAddr)
	addrB := connB.LocalAddr().(*net.UDPAddr)

	a := newBenchNode(idA, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), connA)
	b := newBenchNode(idB, &benchTUN{}, netip.MustParseAddr("10.77.0.6"), connB)
	for _, n := range []*node{a, b} {
		n.seen = map[string]struct{}{}
		n.pings = map[string]pingProbe{}
	}
	a.neighbors[idB.ID] = &peer{ID: idB.ID, Endpoint: addrB.String()}
	b.neighbors[idA.ID] = &peer{ID: idA.ID, Endpoint: addrA.String(), lastRX: time.Now()}
	// The HELLO_ACK reply is routed through nextHop, which needs a usable hop.
	b.routes[idA.ID] = idA.ID
	buffer := make([]byte, 4096)

	// 1. A JSON HELLO from a peer with no compact history is answered with a
	// JSON HELLO_ACK: pre-compact nodes keep the exact pre-change behavior.
	hello := protocol.NewPacket("HELLO", idA.ID, idB.ID, map[string]any{"public_key": idA.Public})
	jsonEncoded, err := protocol.EncodePacket(hello, a.key)
	if err != nil {
		t.Fatal(err)
	}
	b.handleDatagram(jsonEncoded, addrA)
	connA.SetReadDeadline(time.Now().Add(time.Second))
	size, _, err := connA.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.IsCompact(buffer[:size]) || buffer[0] != '{' {
		t.Fatalf("HELLO_ACK toward a JSON-only peer must be JSON, got %d bytes starting %x", size, buffer[:2])
	}
	jsonAck, err := protocol.DecodePacket(buffer[:size], b.key)
	if err != nil || jsonAck.Type != "HELLO_ACK" {
		t.Fatalf("JSON HELLO_ACK decode=%v packet=%+v", err, jsonAck)
	}

	// 2. Once the peer proves compact support, the same HELLO rides the
	// ~70-byte binary format and the reply comes back compact in turn.
	// A fresh packet keeps its own ID: replaying step 1's ID would be
	// dropped by the duplicate filter before reaching the HELLO handler.
	hello2 := protocol.NewPacket("HELLO", idA.ID, idB.ID, map[string]any{"public_key": idA.Public})
	compactHello, err := protocol.EncodeCompact(hello2, a.key)
	if err != nil {
		t.Fatal(err)
	}
	b.handleDatagram(compactHello, addrA)
	connA.SetReadDeadline(time.Now().Add(time.Second))
	size, _, err = connA.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.IsCompact(buffer[:size]) {
		t.Fatalf("HELLO_ACK toward a compact peer must be compact, got %d bytes starting %x", size, buffer[:2])
	}
	compactAck, err := protocol.DecodeCompact(buffer[:size], b.key)
	if err != nil || compactAck.Type != "HELLO_ACK" || compactAck.Source != idB.ID || compactAck.Destination != idA.ID {
		t.Fatalf("compact HELLO_ACK decode=%v packet=%+v", err, compactAck)
	}

	// 3. Receiving the compact HELLO_ACK teaches a that b speaks the binary
	// format, so a's own HELLO probes switch to the compact encoding.
	a.handleDatagram(append([]byte(nil), buffer[:size]...), addrB)
	if !a.speaksCompactHello(idB.ID) {
		t.Fatal("receiving a compact HELLO_ACK must mark the peer compact-capable")
	}
	scanFree := protocol.NewPacket("HELLO", idA.ID, idB.ID, map[string]any{"public_key": idA.Public})
	picked, err := a.encodePacketForPeer(scanFree)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.IsCompact(picked) || len(picked) != protocol.CompactHelloSize {
		t.Fatalf("encodePacketForPeer must pick the compact HELLO, got %d bytes compact=%v", len(picked), protocol.IsCompact(picked))
	}

	// 4. A symmetric-scan HELLO echoes a session_id in HELLO_ACK, so the
	// gating must keep it in the JSON envelope even toward compact peers.
	scanHello := protocol.NewPacket("HELLO", idA.ID, idB.ID, map[string]any{"public_key": idA.Public, "session_id": "abcdef1234567890abcdef123456"})
	picked, err = a.encodePacketForPeer(scanHello)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.IsCompact(picked) || picked[0] != '{' {
		t.Fatalf("session-carrying HELLO must stay JSON, got %d bytes starting %x", len(picked), picked[:2])
	}

	// 5. helloAll targets a capable but not-yet-usable peer with the compact
	// encoding (lastRX is zero, so the peer is not usable and HELLO applies).
	// Step 3's HELLO_ACK made the peer usable via touch; undo that without
	// dropping the learned compact capability.
	a.mu.Lock()
	a.neighbors[idB.ID].lastRX = time.Time{}
	a.neighbors[idB.ID].last = nil
	a.mu.Unlock()
	a.helloAll()
	connB.SetReadDeadline(time.Now().Add(time.Second))
	size, _, err = connB.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.IsCompact(buffer[:size]) {
		t.Fatalf("helloAll must send a compact HELLO to a capable peer, got %d bytes starting %x", size, buffer[:2])
	}
	sent, err := protocol.DecodeCompact(buffer[:size], a.key)
	if err != nil || sent.Type != "HELLO" || sent.Source != idA.ID || sent.Destination != idB.ID {
		t.Fatalf("compact helloAll HELLO decode=%v packet=%+v", err, sent)
	}
}

// encodeCompact and decodeCompact reuse HMAC states from the node's macPool
// rather than building one per frame, so frames sent back to back must still
// round-trip: a pooled state that kept an earlier frame's keyed halves would
// break the tag on the second frame.
func TestCompactReuseAcrossFrames(t *testing.T) {
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
	a.macPool.New = func() any { return protocol.NewPooledMAC(a.key) }
	stamps := []int64{1, 2, 3}
	for _, stamp := range stamps {
		ping := protocol.NewPacket("PING", a.id.ID, b.id.ID, map[string]any{})
		ping.Timestamp = stamp
		encoded, e := a.encodeCompact(ping)
		if e != nil {
			t.Fatal("encodeCompact: ", e)
		}
		back, e := a.decodeCompact(encoded)
		if e != nil {
			t.Fatalf("decodeCompact after stamp %d: %v packet=%+v", stamp, e, back)
		}
		if back.Type != "PING" || back.Source != a.id.ID || back.Destination != b.id.ID {
			t.Fatalf("round trip lost packet identity: %+v", back)
		}
		if back.ID != ping.ID {
			t.Fatalf("round trip changed the packet ID: want %s got %s", ping.ID, back.ID)
		}
	}
}
