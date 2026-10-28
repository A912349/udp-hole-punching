package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

func TestCurrentLinksReportsTrafficConfirmedLAN(t *testing.T) {
	now := time.Now()
	lanAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 40000}
	n := &node{neighbors: map[string]*peer{
		// The most recent datagram arrived from a private address: LAN.
		"lan-peer": {ID: "lan-peer", lastRX: now, lastLAN: lanAddr, lastLANRX: now, lastPathLAN: true},
		// Only public-endpoint traffic observed: internet path even if the
		// peer happens to sit in the same subnet.
		"wan-peer": {ID: "wan-peer", lastRX: now},
		// The peer used to talk over the LAN, but its last packets now come
		// from public addresses (LAN path died): internet.
		"roamed-wan": {ID: "roamed-wan", lastRX: now, lastLAN: lanAddr, lastLANRX: now.Add(-2 * lanHoldTimeout)},
	}}
	byID := map[string]protocol.LinkMeasurement{}
	for _, l := range n.currentLinks() {
		byID[l.PeerID] = l
	}
	if !byID["lan-peer"].ViaLAN || !byID["lan-peer"].Up {
		t.Fatal("traffic from a private source must be reported as an up LAN link")
	}
	if byID["wan-peer"].ViaLAN {
		t.Fatal("public-source traffic must not be reported as LAN")
	}
	if byID["roamed-wan"].ViaLAN {
		t.Fatal("stale LAN observation must not hold the LAN label: the last packets came from public addresses")
	}
}

func TestTouchClassifiesByPacketSource(t *testing.T) {
	n := &node{neighbors: map[string]*peer{
		"peer": {ID: "peer"},
	}}
	// Private source: traffic stayed inside the LAN.
	n.touch("peer", &net.UDPAddr{IP: net.IPv4(192, 168, 5, 7), Port: 40000})
	if p := n.neighbors["peer"]; !p.lastPathLAN || p.lastLAN == nil {
		t.Fatalf("private source must mark the path as LAN: %+v", p)
	}
	// Public source: the traffic left the network, label flips immediately.
	n.touch("peer", &net.UDPAddr{IP: net.IPv4(93, 184, 216, 34), Port: 51000})
	if p := n.neighbors["peer"]; p.lastPathLAN {
		t.Fatalf("public source must flip the path to internet: %+v", p)
	}
	// CGNAT is the provider network, not the LAN.
	n2 := &node{neighbors: map[string]*peer{"peer": {ID: "peer"}}}
	n2.touch("peer", &net.UDPAddr{IP: net.IPv4(100, 64, 1, 2), Port: 40000})
	if p := n2.neighbors["peer"]; p.lastPathLAN {
		t.Fatal("CGNAT source must be classified as internet")
	}
	// Another private subnet of the same physical LAN counts as LAN even
	// though the interface subnets do not cover it.
	n3 := &node{neighbors: map[string]*peer{"peer": {ID: "peer"}}}
	n3.touch("peer", &net.UDPAddr{IP: net.IPv4(10, 200, 1, 2), Port: 40000})
	if p := n3.neighbors["peer"]; !p.lastPathLAN {
		t.Fatal("RFC1918 source from another subnet must be classified as LAN")
	}
}

func TestTelemetryChangedDetectsViaLANFlip(t *testing.T) {
	sent := []protocol.LinkMeasurement{{PeerID: "peer", Up: true, RTTMS: 10}}
	next := []protocol.LinkMeasurement{{PeerID: "peer", Up: true, RTTMS: 10, ViaLAN: true}}
	if !telemetryChanged(sent, next) {
		t.Fatal("LAN-to-internet path transition must be reported")
	}
	if telemetryChanged(next, next) {
		t.Fatal("identical snapshot must not be reported")
	}
}

func TestLinkMeasurementWireFormatKeepsViaLANOptional(t *testing.T) {
	// Older coordinators ignore the new field.
	legacy := []byte(`{"peer_id":"p","rtt_ms":3,"up":true}`)
	var m protocol.LinkMeasurement
	if err := json.Unmarshal(legacy, &m); err != nil {
		t.Fatal(err)
	}
	if m.ViaLAN || m.PeerID != "p" || !m.Up {
		t.Fatalf("legacy telemetry decoded incorrectly: %+v", m)
	}
	// Newer nodes send the field and it survives a round trip.
	encoded, err := json.Marshal(protocol.LinkMeasurement{PeerID: "p", Up: true, ViaLAN: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"peer_id":"p","rtt_ms":0,"up":true,"via_lan":true}` {
		t.Fatalf("unexpected wire format: %s", encoded)
	}
}
