package main

import (
	"encoding/hex"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

func TestNextHopThrottlesRouteRecomputation(t *testing.T) {
	self, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	neighbor, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(neighbor.ID)
	if err != nil || len(decoded) != 16 {
		t.Fatalf("invalid neighbor identity: %v", err)
	}
	n := &node{
		id:         self,
		dir:        map[string]*peer{},
		neighbors:  map[string]*peer{},
		routes:     map[string]string{},
		links:      []edge{{A: self.ID, B: neighbor.ID, Cost: 1}},
		sharedKeys: map[string]cachedKey{},
	}
	n.neighbors[neighbor.ID] = &peer{ID: neighbor.ID, Endpoint: "127.0.0.1:23001", lastRX: time.Now()}

	hop, p := n.nextHop(neighbor.ID)
	if hop != neighbor.ID || p == nil {
		t.Fatalf("first lookup = %q, want the direct neighbor", hop)
	}

	// A second destination while the recompute window is active must not run
	// another Dijkstra; it returns no route until the window elapses.
	hop2, p2 := n.nextHop(other.ID)
	if hop2 != "" || p2 != nil {
		t.Fatalf("throttled recompute returned hop %q", hop2)
	}
}
