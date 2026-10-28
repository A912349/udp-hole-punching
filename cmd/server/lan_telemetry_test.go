package main

import (
	"encoding/json"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

func TestUpdateLinkMetricsDetectsViaLANTransition(t *testing.T) {
	s := &server{metrics: map[string]linkMetric{}}
	first := []protocol.LinkMeasurement{{PeerID: "peer", Up: true, RTTMS: 5}}
	if !s.updateLinkMetrics("self", first) {
		t.Fatal("first sighting must invalidate the cached graph")
	}
	if s.updateLinkMetrics("self", first) {
		t.Fatal("unchanged report must not invalidate the cached graph")
	}
	second := []protocol.LinkMeasurement{{PeerID: "peer", Up: true, RTTMS: 5, ViaLAN: true}}
	if !s.updateLinkMetrics("self", second) {
		t.Fatal("LAN path transition must invalidate the cached graph")
	}
	if !s.metrics[metricKey("self", "peer")].ViaLAN {
		t.Fatal("LAN observation was not stored")
	}
}

func TestDecorateLinksMarksTelemetryConfirmedLANEdges(t *testing.T) {
	now := time.Now()
	fresh := func() linkMetric { return linkMetric{Up: true, Seen: now} }

	// Forward direction observed a LAN path.
	s := &server{metrics: map[string]linkMetric{metricKey("a", "b"): {Up: true, ViaLAN: true, Seen: now}}}
	ls := s.decorateLinks([]link{{A: "a", B: "b", Cost: 1}})
	if !ls[0].ViaLAN {
		t.Fatal("fresh forward LAN observation must mark the edge as LAN")
	}

	// Only the reverse direction observed a LAN path.
	s = &server{metrics: map[string]linkMetric{metricKey("b", "a"): {Up: true, ViaLAN: true, Seen: now}}}
	ls = s.decorateLinks([]link{{A: "a", B: "b", Cost: 1}})
	if !ls[0].ViaLAN {
		t.Fatal("fresh reverse LAN observation must mark the edge as LAN")
	}

	// Observation is stale: the edge falls back to the internet path.
	s = &server{metrics: map[string]linkMetric{metricKey("a", "b"): {Up: true, ViaLAN: true, Seen: now.Add(-time.Minute)}}}
	ls = s.decorateLinks([]link{{A: "a", B: "b", Cost: 1}})
	if ls[0].ViaLAN {
		t.Fatal("stale LAN observation must not mark the edge as LAN")
	}

	// Fresh telemetry without LAN traffic stays an internet edge.
	s = &server{metrics: map[string]linkMetric{metricKey("a", "b"): fresh()}}
	ls = s.decorateLinks([]link{{A: "a", B: "b", Cost: 1}})
	if ls[0].ViaLAN {
		t.Fatal("edge without LAN observations must stay an internet edge")
	}
}

func TestTopologyJSONExposesViaLAN(t *testing.T) {
	raw, err := json.Marshal(link{A: "a", B: "b", Cost: 1, Status: "up", ViaLAN: true})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["via_lan"] != true {
		t.Fatalf("via_lan missing from topology JSON: %s", raw)
	}
	internet, err := json.Marshal(link{A: "a", B: "b", Cost: 1, Status: "up"})
	if err != nil {
		t.Fatal(err)
	}
	decoded = map[string]any{}
	if err := json.Unmarshal(internet, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["via_lan"]; ok {
		t.Fatal("internet edges must not emit via_lan")
	}
}

func TestSanitizeLanAddrsDropsInvalidEntries(t *testing.T) {
	out := sanitizeLanAddrs([]string{
		"192.168.1.20:40000",
		" 10.0.0.5:33  ",
		"999.1.1.1:1",
		"192.168.1.3",
		"192.168.1.4:0",
		"192.168.1.5:70000",
		"fe80::1:40000",
		"127.0.0.1:5000",
	})
	want := []string{"192.168.1.20:40000", "10.0.0.5:33"}
	if len(out) != len(want) {
		t.Fatalf("sanitizeLanAddrs = %v, want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("sanitizeLanAddrs[%d] = %q, want %q", i, out[i], want[i])
		}
	}
}
