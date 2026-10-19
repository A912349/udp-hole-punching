package main

// These tests cover idle traffic behavior and regression cases.
import (
	"net"
	"net/netip"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

func TestHelloSkipsHealthyPeerButKeepsPing(t *testing.T) {
	id, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	n := newBenchNode(id, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), conn)
	neighbor := &peer{ID: "neighbor", Endpoint: remote.LocalAddr().String(), last: remote.LocalAddr(), lastRX: time.Now()}
	n.neighbors[neighbor.ID] = neighbor
	n.pings = make(map[string]pingProbe)
	n.helloAll()
	// PING is still sent with no added delay. It must be the first datagram,
	// proving helloAll did not enqueue an unnecessary HELLO for a healthy peer.
	n.pingAll()
	buffer := make([]byte, 4096)
	readType := func(want string) {
		t.Helper()
		remote.SetReadDeadline(time.Now().Add(time.Second))
		size, _, err := remote.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := protocol.DecodePacket(buffer[:size], n.key)
		if err != nil || packet.Type != want {
			t.Fatalf("packet type=%q err=%v, want %s", packet.Type, err, want)
		}
	}
	readType("PING")
	neighbor.lastRX = time.Now().Add(-linkTimeout - time.Second)
	n.helloAll()
	readType("HELLO")
	neighbor.lastRX = time.Time{}
	n.helloAll()
	readType("HELLO")
}

func TestConditionalTopologyDoesNotReplaceNewerPush(t *testing.T) {
	n := &node{topologyVersion: "newer", neighbors: map[string]*peer{"peer": {ID: "peer"}}}
	n.applyTopology(topology{Version: "older", Unchanged: true})
	if n.topologyVersion != "newer" || n.neighbors["peer"] == nil {
		t.Fatal("conditional response replaced an already installed topology")
	}
}
