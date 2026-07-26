package main

import (
	"net"
	"reflect"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

func TestSymmetricScanPortsUsesSparseDescendingPasses(t *testing.T) {
	const center, step = 54532, 200
	ports := make([]int, 0, 329)
	symmetricScanPorts(center, step, func(port int) bool {
		ports = append(ports, port)
		return len(ports) < cap(ports)
	})

	if got, want := ports[:3], []int{54332, 54732, 54932}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scan begins with %v, want %v", got, want)
	}
	wrapAt := -1
	for i, port := range ports {
		if port == 65532 {
			wrapAt = i
			break
		}
	}
	if wrapAt == -1 || wrapAt+1 >= len(ports) || ports[wrapAt+1] != 132 {
		t.Fatalf("scan did not wrap from 65532 to 132: %v", ports)
	}
	if got := ports[len(ports)-2]; got != center {
		t.Fatalf("first pass ends at %d, want target port %d", got, center)
	}
	if got := ports[len(ports)-1]; got != 54331 {
		t.Fatalf("second pass begins at %d, want 54331", got)
	}
}

func TestEstablishSymmetricTransportSkipsNonSymmetricNAT(t *testing.T) {
	n := &node{c: config{nat: "cone"}}
	if !n.establishSymmetricTransport() {
		t.Fatal("non-symmetric NAT should not require symmetric transport")
	}
}

func TestEndpointIPChangedIgnoresPortChanges(t *testing.T) {
	if endpointIPChanged("198.51.100.7:4000", "198.51.100.7:5000") {
		t.Fatal("port-only endpoint change must not require re-registration")
	}
	if !endpointIPChanged("198.51.100.7:4000", "198.51.100.8:4000") {
		t.Fatal("IP endpoint change must require re-registration")
	}
	if !endpointIPChanged("[2001:db8::7]:4000", "[2001:db8::8]:5000") {
		t.Fatal("IPv6 endpoint IP change must require re-registration")
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

func TestHandlePongTracksOnlyDirectExpectedProbe(t *testing.T) {
	const probeID = "probe-id"
	n := &node{
		neighbors: map[string]*peer{"peer": {}},
		pings: map[string]pingProbe{
			probeID: {sent: time.Now().Add(-5 * time.Millisecond), peerID: "peer"},
		},
	}

	relayed := protocol.Packet{Source: "peer", TTL: protocol.DefaultTTL - 1, Payload: map[string]any{"ping_id": probeID}}
	n.handlePong(relayed)
	if n.neighbors["peer"].rttMS != 0 {
		t.Fatal("relayed PONG changed direct-link RTT")
	}
	if _, exists := n.pings[probeID]; !exists {
		t.Fatal("relayed PONG consumed the direct probe")
	}

	wrongPeer := protocol.Packet{Source: "other", TTL: protocol.DefaultTTL, Payload: map[string]any{"ping_id": probeID}}
	n.handlePong(wrongPeer)
	if _, exists := n.pings[probeID]; !exists {
		t.Fatal("PONG from another peer consumed the probe")
	}

	direct := protocol.Packet{Source: "peer", TTL: protocol.DefaultTTL, Payload: map[string]any{"ping_id": probeID}}
	n.handlePong(direct)
	if n.neighbors["peer"].rttMS <= 0 {
		t.Fatal("direct PONG did not update RTT")
	}
	if _, exists := n.pings[probeID]; exists {
		t.Fatal("direct PONG did not consume its probe")
	}
}
