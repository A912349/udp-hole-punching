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
		// Fresh traffic from the peer's LAN address: measured LAN path.
		"lan-peer": {ID: "lan-peer", lastRX: now, lastLAN: lanAddr, lastLANRX: now},
		// Only public-endpoint traffic observed: internet path even if the
		// peer happens to sit in the same subnet.
		"wan-peer": {ID: "wan-peer", lastRX: now},
		// LAN address went stale: the LAN path can no longer be confirmed.
		"stale-lan": {ID: "stale-lan", lastRX: now, lastLAN: lanAddr, lastLANRX: now.Add(-2 * lanHoldTimeout)},
	}}
	byID := map[string]protocol.LinkMeasurement{}
	for _, l := range n.currentLinks() {
		byID[l.PeerID] = l
	}
	if !byID["lan-peer"].ViaLAN || !byID["lan-peer"].Up {
		t.Fatal("fresh LAN traffic must be reported as an up LAN link")
	}
	if byID["wan-peer"].ViaLAN {
		t.Fatal("public-endpoint traffic must not be reported as LAN")
	}
	if byID["stale-lan"].ViaLAN {
		t.Fatal("stale LAN observation must not be reported as LAN")
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
