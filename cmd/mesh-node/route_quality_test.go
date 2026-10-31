package main

import (
	"net"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

// routeTestNode builds a diamond: self -> primary (1) -> dest (1) is the
// cheapest path, self -> backup (2) -> dest (1) is the fallback.
func routeTestNode(t *testing.T) (n *node, primary, backup, dest string) {
	t.Helper()
	newID := func() string {
		id, err := protocol.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		return id.ID
	}
	self, primary, backup, dest := newID(), newID(), newID(), newID()
	n = &node{
		id:         &protocol.Identity{ID: self},
		key:        []byte("unit-test-network-key"),
		dir:        map[string]*peer{},
		neighbors:  map[string]*peer{},
		routes:     map[string]string{},
		altRoutes:  map[string]string{},
		sharedKeys: map[string]cachedKey{},
		links: []edge{
			{A: self, B: primary, Cost: 1},
			{A: primary, B: dest, Cost: 1},
			{A: self, B: backup, Cost: 2},
			{A: backup, B: dest, Cost: 1},
		},
	}
	now := time.Now()
	for _, id := range []string{primary, backup} {
		n.dir[id] = &peer{ID: id}
		n.neighbors[id] = &peer{ID: id, Endpoint: "127.0.0.1:40000", lastRX: now}
	}
	// dest is two hops away: known to the directory, but not a direct peer.
	n.dir[dest] = &peer{ID: dest}
	return n, primary, backup, dest
}

func TestComputeRoutesBuildsFallbackTable(t *testing.T) {
	n, primary, backup, dest := routeTestNode(t)
	n.mu.RLock()
	routes, fallbacks := n.computeRoutes()
	n.mu.RUnlock()
	if routes[dest] != primary {
		t.Fatalf("primary route = %q, want %q", routes[dest], primary)
	}
	if routes[primary] != primary || routes[backup] != backup {
		t.Fatalf("usable direct neighbors must route directly: %q %q", routes[primary], routes[backup])
	}
	if fallbacks[dest] != backup {
		t.Fatalf("fallback route = %q, want %q", fallbacks[dest], backup)
	}
	if _, ok := fallbacks[backup]; ok {
		t.Fatal("a usable direct neighbor needs no fallback hop")
	}
	// With the primary edge dead the same link set must produce a table
	// that routes around it entirely.
	n.mu.Lock()
	n.neighbors[primary].lastRX = time.Now().Add(-linkTimeout - time.Second)
	n.mu.Unlock()
	n.mu.RLock()
	rerouted, _ := n.computeRoutes()
	n.mu.RUnlock()
	if rerouted[dest] != backup {
		t.Fatalf("route with dead primary = %q, want %q", rerouted[dest], backup)
	}
}

func TestSendFallsBackToAlternateHop(t *testing.T) {
	n, primary, backup, dest := routeTestNode(t)
	n.mu.RLock()
	routes, fallbacks := n.computeRoutes()
	n.mu.RUnlock()
	n.mu.Lock()
	n.routes, n.altRoutes = routes, fallbacks
	// The primary edge just died while the 250 ms recompute window is
	// active: nextHop cannot repair the table and returns nothing, so send
	// must try the precomputed alternate hop instead of dropping.
	n.neighbors[primary].lastRX = time.Now().Add(-linkTimeout - time.Second)
	n.routeRecompute.Store(time.Now().UnixNano())
	n.mu.Unlock()

	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	n.mu.Lock()
	n.conn = conn
	n.neighbors[backup].last = sink.LocalAddr().(*net.UDPAddr)
	n.mu.Unlock()

	p := protocol.NewPacket("DATA", n.id.ID, dest, map[string]any{"sealed": map[string]string{"v": "x"}})
	if !n.send(p) {
		t.Fatal("send must deliver via the precomputed alternate hop")
	}
	sink.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	if _, _, err := sink.ReadFromUDP(buf); err != nil {
		t.Fatalf("fallback datagram did not arrive: %v", err)
	}
}

func TestPongSmoothsRTTAndDecaysLoss(t *testing.T) {
	self, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerID := "0123456789abcdef0123456789abcdef"
	n := &node{
		id:        self,
		neighbors: map[string]*peer{peerID: {ID: peerID, rttMS: 100, lossEMA: 0.5}},
		pings:     map[string]pingProbe{},
	}
	n.pings["p1"] = pingProbe{sent: time.Now().Add(-10 * time.Millisecond), peerID: peerID}
	n.handlePong(protocol.Packet{
		Type: "PONG", Source: peerID, Destination: self.ID,
		TTL:     protocol.DefaultTTL,
		Payload: map[string]any{"ping_id": "p1"},
	})
	p := n.neighbors[peerID]
	// 0.7*100 + 0.3*10 = 73: one delayed probe must not replace the estimate.
	if p.rttMS < 72 || p.rttMS > 74 {
		t.Fatalf("rtt EMA = %.2f, want ~73", p.rttMS)
	}
	if p.lossEMA < 0.44 || p.lossEMA > 0.46 {
		t.Fatalf("answered probe must decay loss toward 0.45, got %.3f", p.lossEMA)
	}
}

func TestExpiredProbesRaiseLoss(t *testing.T) {
	self, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerID := "0123456789abcdef0123456789abcdef"
	n := &node{
		id:        self,
		neighbors: map[string]*peer{peerID: {ID: peerID}},
		pings: map[string]pingProbe{
			"old": {sent: time.Now().Add(-2 * linkTimeout), peerID: peerID},
			"new": {sent: time.Now(), peerID: peerID},
		},
	}
	lost := prunePings(n.pings, time.Now().Add(-linkTimeout))
	if len(lost) != 1 || lost[0] != peerID {
		t.Fatalf("pruned probes = %v, want [%s]", lost, peerID)
	}
	if _, ok := n.pings["old"]; ok {
		t.Fatal("expired probe was not pruned")
	}
	n.noteLostProbes(lost)
	if p := n.neighbors[peerID]; p.lossEMA < 0.099 || p.lossEMA > 0.101 {
		t.Fatalf("one expired round must raise loss to ~0.1, got %.3f", p.lossEMA)
	}
	n.noteLostProbes(lost)
	if p := n.neighbors[peerID]; p.lossEMA < 0.189 || p.lossEMA > 0.191 {
		t.Fatalf("two expired rounds must raise loss to ~0.19, got %.3f", p.lossEMA)
	}
}

func TestTopologyRefreshKeepsMeasuredQuality(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	self := "fedcba9876543210fedcba9876543210"
	n := &node{id: &protocol.Identity{ID: self}, neighbors: map[string]*peer{}, routes: map[string]string{}, altRoutes: map[string]string{}}
	n.applyTopology(topology{Version: "v1", Self: peer{ID: self}, Neighbors: []peer{{ID: id}}})
	n.mu.Lock()
	n.neighbors[id].rttMS = 84
	n.neighbors[id].lossEMA = 0.25
	n.mu.Unlock()
	// Every topology push rebuilt the peer structs; the measured quality
	// must survive the refresh instead of resetting to zero.
	n.applyTopology(topology{Version: "v2", Self: peer{ID: self}, Neighbors: []peer{{ID: id}}})
	p := n.neighbors[id]
	if p == nil || p.rttMS != 84 || p.lossEMA != 0.25 {
		t.Fatalf("measured quality lost across topology refresh: %+v", p)
	}
	for _, l := range n.currentLinks() {
		if l.PeerID == id && (l.RTTMS != 84 || l.Loss != 0.25) {
			t.Fatalf("telemetry must carry smoothed measurements: %+v", l)
		}
	}
}

func TestTelemetryChangedDetectsLossDrift(t *testing.T) {
	sent := []protocol.LinkMeasurement{{PeerID: "p", RTTMS: 20, Up: true}}
	if telemetryChanged(sent, []protocol.LinkMeasurement{{PeerID: "p", RTTMS: 20, Up: true, Loss: 0.05}}) {
		t.Fatal("sub-step loss jitter must not trigger a telemetry report")
	}
	if !telemetryChanged(sent, []protocol.LinkMeasurement{{PeerID: "p", RTTMS: 20, Up: true, Loss: 0.2}}) {
		t.Fatal("a meaningful loss step must trigger a telemetry report")
	}
}
