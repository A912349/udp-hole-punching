package main

import (
	"net"
	"testing"

	"home-udp-mesh/internal/protocol"
)

// A port-only NAT rebinding must update the advertised endpoint and NAT
// classification without clearing the cached peer observations: existing
// links are re-taught through hello/ping, not torn down.
func TestApplyEndpointChangePortOnlyKeepsPeerState(t *testing.T) {
	n := &node{
		id:           &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"},
		c:            config{endpoint: "1.2.3.4:1111", nat: "cone"},
		requestedNAT: "auto",
		neighbors: map[string]*peer{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {Endpoint: "5.6.7.8:9999", up: true, last: &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9999}},
		},
	}

	n.applyEndpointChange("1.2.3.4:1111", "1.2.3.4:2222", "cone", "test")

	if n.c.endpoint != "1.2.3.4:2222" {
		t.Fatalf("port-only change must update the advertised endpoint, got %s", n.c.endpoint)
	}
	if n.c.nat != "cone" {
		t.Fatalf("requestedNAT=auto must adopt the fresh NAT type, got %s", n.c.nat)
	}
	n.mu.RLock()
	peer := n.neighbors["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
	up, last := peer.up, peer.last
	n.mu.RUnlock()
	if !up || last == nil {
		t.Fatal("port-only change must not clear cached peer observations")
	}
}

// An IP change must rebuild the transport and clear cached peer observations
// (they point at the dead mapping) even when re-registration itself fails,
// so the next recovery pass starts from a clean slate.
func TestApplyEndpointChangeIPClearsPeerState(t *testing.T) {
	n := &node{
		id:           &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"},
		c:            config{endpoint: "1.2.3.4:1111", nat: "cone"},
		requestedNAT: "auto",
		neighbors: map[string]*peer{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {Endpoint: "5.6.7.8:9999", up: true, last: &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9999}},
		},
	}

	// n.c.server is empty, so re-register fails fast without touching the
	// network; the endpoint adoption and transport reset must still happen.
	n.applyEndpointChange("1.2.3.4:1111", "9.9.9.9:5555", "cone", "test")

	if n.c.endpoint != "9.9.9.9:5555" {
		t.Fatalf("IP change must update the advertised endpoint, got %s", n.c.endpoint)
	}
	n.mu.RLock()
	peer := n.neighbors["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
	up, last := peer.up, peer.last
	n.mu.RUnlock()
	if up || last != nil {
		t.Fatal("IP change must clear cached peer observations (stale mapping)")
	}
}

// verifyEndpoint must be a no-op while no endpoint is known yet (startup).
func TestVerifyEndpointSkipsWithoutEndpoint(t *testing.T) {
	n := &node{id: &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"}}
	n.verifyEndpoint() // must not panic or dial STUN
	if n.c.endpoint != "" {
		t.Fatalf("verify must not invent an endpoint, got %s", n.c.endpoint)
	}
}
