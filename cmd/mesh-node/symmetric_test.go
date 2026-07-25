package main

import (
	"testing"
	"time"
)

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
		if !confirmsDirectPath(packetType) {
			t.Fatalf("%s should confirm a direct path", packetType)
		}
	}
	for _, packetType := range []string{"SYMMETRIC_BURST", "DATA", "IP"} {
		if confirmsDirectPath(packetType) {
			t.Fatalf("%s must not confirm a bidirectional direct path", packetType)
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
	cancel := make(chan struct{})
	n := &node{
		symmetricScans:     map[string]chan struct{}{"peer": cancel},
		symmetricSessions:  map[string]string{"peer": "current"},
		symmetricConnected: map[string]bool{},
	}
	n.completeSymmetricScan("peer", "stale")
	select {
	case <-cancel:
		t.Fatal("stale session completed the current scan")
	default:
	}
	n.completeSymmetricScan("peer", "current")
	select {
	case <-cancel:
	default:
		t.Fatal("matching session did not complete the scan")
	}
	if !n.symmetricConnected["peer"] {
		t.Fatal("peer was not marked connected")
	}
}
