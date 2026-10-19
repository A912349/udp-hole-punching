package main

// These tests cover compact keepalive behavior and regression cases.
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
