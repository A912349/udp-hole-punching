package main

import (
	"net"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

func TestEstablishSymmetricTransportSkipsNonSymmetricNAT(t *testing.T) {
	n := &node{c: config{nat: "cone"}}
	if !n.establishSymmetricTransport() {
		t.Fatal("non-symmetric NAT should not require symmetric transport")
	}
}

func TestCancelObsoleteSymmetricScans(t *testing.T) {
	kept := make(chan struct{})
	removed := make(chan struct{})
	n := &node{
		neighbors:          map[string]*peer{"kept": {}},
		symmetricScans:     map[string]chan struct{}{"kept": kept, "removed": removed},
		symmetricConnected: map[string]bool{"removed": true},
		symmetricBurstAt:   map[string]time.Time{},
	}
	n.cancelObsoleteSymmetricScans()
	if n.symmetricScans["kept"] != kept {
		t.Fatal("scan for a current neighbor was cancelled")
	}
	if _, ok := n.symmetricScans["removed"]; ok {
		t.Fatal("obsolete scan was retained")
	}
	select {
	case <-removed:
	default:
		t.Fatal("obsolete scan cancellation channel was not closed")
	}
}

func TestOnlyDirectHandshakeTrafficRefreshesPath(t *testing.T) {
	for _, packetType := range []string{"HELLO", "HELLO_ACK", "PING", "PONG"} {
		if !confirmsDirectPath(packetType, protocol.DefaultTTL) {
			t.Fatalf("%s should confirm a direct path", packetType)
		}
	}
	for _, packetType := range []string{"SYMMETRIC_BURST", "DATA", "IP"} {
		if confirmsDirectPath(packetType, protocol.DefaultTTL) {
			t.Fatalf("%s must not confirm a bidirectional direct path", packetType)
		}
	}
	for _, packetType := range []string{"HELLO", "HELLO_ACK", "PING", "PONG"} {
		if confirmsDirectPath(packetType, protocol.DefaultTTL-1) {
			t.Fatalf("relayed %s must not refresh the direct path", packetType)
		}
	}
}

func TestSymmetricRelaySelectionIsDeterministic(t *testing.T) {
	n := &node{neighbors: map[string]*peer{
		"relay-z": {ID: "relay-z", Role: "superpeer"},
		"relay-a": {ID: "relay-a", Role: "superpeer"},
		"client":  {ID: "client", Role: "client"},
	}}
	id, _ := n.symmetricRelay()
	if id != "relay-a" {
		t.Fatalf("selected relay %q, want relay-a", id)
	}
}

func TestSymmetricRelaysIncludesAllSuperpeers(t *testing.T) {
	n := &node{neighbors: map[string]*peer{
		"relay-z": {ID: "relay-z", Role: "superpeer"},
		"relay-a": {ID: "relay-a", Role: "superpeer"},
		"client":  {ID: "client", Role: "client"},
	}}
	relays := n.symmetricRelays()
	if len(relays) != 2 || relays[0].id != "relay-a" || relays[1].id != "relay-z" {
		t.Fatalf("relays = %#v, want relay-a and relay-z in deterministic order", relays)
	}
}

func TestConnForPeerUsesDedicatedSymmetricSocket(t *testing.T) {
	primary, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	dedicated, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer dedicated.Close()
	n := &node{
		c:              config{nat: "symmetric"},
		conn:           primary,
		symmetricConns: map[string]*net.UDPConn{"relay": dedicated},
	}
	if got := n.connForPeer("relay"); got != dedicated {
		t.Fatal("dedicated symmetric socket was not selected")
	}
	if got := n.connForPeer("other"); got != primary {
		t.Fatal("primary socket was not used as fallback")
	}
}

func TestNextHopBypassesDeadDirectNeighbor(t *testing.T) {
	const selfID, destinationID, relayID = "self-0000", "dest-0000", "relay-00"
	n := &node{
		id:     &protocol.Identity{ID: selfID},
		routes: map[string]string{destinationID: destinationID},
		neighbors: map[string]*peer{
			destinationID: {ID: destinationID},
			relayID:       {ID: relayID, lastRX: time.Now()},
		},
		links: []edge{
			{A: selfID, B: destinationID, Cost: 1},
			{A: selfID, B: relayID, Cost: 1},
			{A: relayID, B: destinationID, Cost: 1},
		},
	}
	hop, peer := n.nextHop(destinationID)
	if hop != relayID || peer != n.neighbors[relayID] {
		t.Fatalf("dead direct neighbor selected: hop=%q, want relay %q", hop, relayID)
	}
}

func TestResetTransportStateForcesFreshHandshake(t *testing.T) {
	cancel := make(chan struct{})
	n := &node{
		neighbors:          map[string]*peer{"peer": {lastRX: time.Now(), up: true}},
		symmetricReady:     true,
		symmetricScans:     map[string]chan struct{}{"peer": cancel},
		symmetricConnected: map[string]bool{"peer": true},
		symmetricBurstAt:   map[string]time.Time{"peer": time.Now()},
	}
	n.resetTransportState()
	if n.symmetricReady || len(n.symmetricConnected) != 0 || len(n.symmetricScans) != 0 {
		t.Fatal("symmetric transport state survived network recovery reset")
	}
	if !n.neighbors["peer"].lastRX.IsZero() || n.neighbors["peer"].up {
		t.Fatal("stale peer liveness survived network recovery reset")
	}
	select {
	case <-cancel:
	default:
		t.Fatal("active scan was not cancelled")
	}
}

func TestCompleteSymmetricScanRequiresMatchingSession(t *testing.T) {
	const peerID = "peer-id-1234"
	cancel := make(chan struct{})
	n := &node{
		symmetricScans:     map[string]chan struct{}{peerID: cancel},
		symmetricSessions:  map[string]string{peerID: "current"},
		symmetricConnected: map[string]bool{},
	}
	n.completeSymmetricScan(peerID, "stale")
	select {
	case <-cancel:
		t.Fatal("stale session completed the current scan")
	default:
	}
	n.completeSymmetricScan(peerID, "current")
	select {
	case <-cancel:
	default:
		t.Fatal("matching session did not complete the scan")
	}
	if !n.symmetricConnected[peerID] {
		t.Fatal("peer was not marked connected")
	}
}
