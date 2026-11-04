package main

import (
	"net"
	"testing"
)

// A provider UDP hole is a NAT punched on the ISP network whose published
// endpoint can carry a PRIVATE address inside a neighboring network (e.g.
// 192.168.1.54 inside 192.168.1.0/24). The range heuristic alone cannot
// tell such a source from LAN traffic, so classification must consult the
// published NAT endpoint instead.

func TestTouchHoleInsidePrivateRangeIsInternet(t *testing.T) {
	// 192.168.2.0/24 (this node) talks to the peer over the provider's UDP
	// hole punched at 192.168.1.54, a private address inside the neighbor's
	// network: indistinguishable from LAN by range alone.
	n := &node{neighbors: map[string]*peer{
		"peer": {ID: "peer", Endpoint: "192.168.1.54:41820"},
	}}
	n.touch("peer", &net.UDPAddr{IP: net.IPv4(192, 168, 1, 54), Port: 41820})
	p := n.neighbors["peer"]
	if p.lastPathLAN || p.lastLAN != nil {
		t.Fatal("hole endpoint must not be adopted as LAN")
	}
	// The same peer now answers from its own published LAN address (where it
	// really lives, one NAT hop away): that is LAN traffic and must confirm
	// the local path.
	n.touch("peer", &net.UDPAddr{IP: net.IPv4(192, 168, 2, 137), Port: 41820})
	if p := n.neighbors["peer"]; !p.lastPathLAN || p.lastLAN == nil {
		t.Fatal("published LAN addr of the source must confirm the LAN path")
	}
}

func TestTouchOwnHoleRoundTripIsInternet(t *testing.T) {
	// A keepalive/HELLO unicasted to this node's own advertised LAN addr can
	// return through the very hole it left: the reply arrives FROM the node's
	// own endpoint address. Self round trips are NAT traffic even when the
	// endpoint looks private; adopting them would relight the provider hole
	// every probe round (ping and shared bandwidth).
	n := &node{
		c: config{endpoint: "192.168.1.54:41820"},
		neighbors: map[string]*peer{"peer": {ID: "peer"}},
	}
	n.touch("peer", &net.UDPAddr{IP: net.IPv4(192, 168, 1, 54), Port: 41820})
	if p := n.neighbors["peer"]; p.lastPathLAN || p.lastLAN != nil {
		t.Fatal("self round trip through own hole must not be LAN")
	}
}

func TestTouchIdentityNATStaysLAN(t *testing.T) {
	// Identity NAT on the same network: the endpoint equals the node's own
	// LAN address, so the published-LAN-address rule must win over the
	// external-endpoint rule and keep the LAN label.
	n := &node{neighbors: map[string]*peer{
		"neighbor": {ID: "neighbor",
			Endpoint: "10.200.1.2:41820",
			LANAddrs: []string{"10.200.1.2:41820"}},
	}}
	n.touch("neighbor", &net.UDPAddr{IP: net.IPv4(10, 200, 1, 2), Port: 41820})
	if p := n.neighbors["neighbor"]; !p.lastPathLAN {
		t.Fatal("identity-NAT source at its published LAN addr must stay LAN")
	}
}

func TestLanCandidateBlockedIPOwnAndPeerHole(t *testing.T) {
	// Probe/adopt sites must reject candidates that equal a published NAT
	// endpoint even when the hole carries a private address; hostname
	// endpoints never match.
	remote := "203.0.113.9:41820"
	// Own hole: unicasting toward it goes out and comes back: probe skip.
	ownHole := net.IPv4(192, 168, 1, 54)
	remoteHole := net.IPv4(203, 0, 113, 9)
	home := net.IPv4(192, 168, 1, 77)
	// Own hole: unicasting toward it goes out and comes back: probe skip.
	if !lanCandidateBlockedIP(ownHole, "192.168.1.54:41820") {
		t.Fatal("own private-looking hole must block the candidate")
	}
	if !lanCandidateBlockedIP(remoteHole, "192.168.1.54:41820", remote) {
		t.Fatal("peer hole endpoint must block the candidate")
	}
	if lanCandidateBlockedIP(ownHole, remote) {
		t.Fatal("a public endpoint that is not the candidate must not block")
	}
	if lanCandidateBlockedIP(home, "192.168.1.54:41820", remote) {
		t.Fatal("a private addr that is no endpoint stays a valid candidate")
	}
	if lanCandidateBlockedIP(ownHole, "relay.example:41820") {
		t.Fatal("a hostname endpoint never matches a numeric candidate")
	}
}
