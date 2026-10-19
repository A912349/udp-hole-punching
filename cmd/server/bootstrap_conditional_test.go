package main

// These tests cover bootstrap conditional behavior and regression cases.
import (
	"encoding/json"
	"net/http"
	"testing"

	"home-udp-mesh/internal/protocol"
)

func TestConditionalBootstrap(t *testing.T) {
	s := testAuthServer(t)
	identity, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{
		"node_id": identity.ID, "public_key": identity.Public, "nat_type": "cone",
		"role": "auto", "endpoint": "127.0.0.1:23001", "capacity": 1,
	})
	register := func() {
		t.Helper()
		result := s.controlRequest(controlFrame{Method: http.MethodPost, Path: "/v1/register", Body: data})
		if result.Status != 200 {
			t.Fatalf("register: %+v", result)
		}
	}
	register()
	path := "/v1/bootstrap/" + identity.ID
	full := s.controlRequest(controlFrame{Method: http.MethodGet, Path: path})
	if full.Status != 200 {
		t.Fatalf("bootstrap: %+v", full)
	}
	var snapshot map[string]json.RawMessage
	if err := json.Unmarshal(full.Body, &snapshot); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := json.Unmarshal(snapshot["topology_version"], &version); err != nil || version == "" {
		t.Fatalf("version: %q %v", version, err)
	}
	// Simulate a later registration heartbeat, not just a same-second request.
	if _, err := s.db.Exec("UPDATE nodes SET last_seen=last_seen+1 WHERE node_id=?", identity.ID); err != nil {
		t.Fatal(err)
	}
	condition, _ := json.Marshal(map[string]string{"version": version})
	small := s.controlRequest(controlFrame{Method: http.MethodGet, Path: path, Body: condition})
	if small.Status != 200 {
		t.Fatalf("conditional bootstrap: %+v", small)
	}
	var reduced map[string]json.RawMessage
	if err := json.Unmarshal(small.Body, &reduced); err != nil {
		t.Fatal(err)
	}
	if len(reduced) != 2 || string(reduced["unchanged"]) != "true" || string(reduced["topology_version"]) != string(snapshot["topology_version"]) {
		t.Fatalf("expected version-only response: %s", small.Body)
	}
	t.Logf("bootstrap payload: full=%d bytes, unchanged=%d bytes", len(full.Body), len(small.Body))
	// Endpoint changes must invalidate the condition and return the full view.
	if _, err := s.db.Exec("UPDATE nodes SET endpoint='127.0.0.1:23002' WHERE node_id=?", identity.ID); err != nil {
		t.Fatal(err)
	}
	changed := s.controlRequest(controlFrame{Method: http.MethodGet, Path: path, Body: condition})
	if changed.Status != 200 {
		t.Fatalf("changed bootstrap: %+v", changed)
	}
	var updated map[string]json.RawMessage
	if err := json.Unmarshal(changed.Body, &updated); err != nil {
		t.Fatal(err)
	}
	if len(updated) <= 2 || string(updated["topology_version"]) == string(snapshot["topology_version"]) {
		t.Fatalf("endpoint change hidden: %s", changed.Body)
	}
	legacy := s.controlRequest(controlFrame{Method: http.MethodGet, Path: path})
	if len(legacy.Body) <= len(small.Body) {
		t.Fatal("legacy request no longer returns full topology")
	}
	bad := s.controlRequest(controlFrame{Method: http.MethodGet, Path: path, Body: json.RawMessage(`{"version":1}`)})
	if bad.Status != http.StatusBadRequest {
		t.Fatalf("invalid condition status: %d", bad.Status)
	}
}

func TestBootstrapVersionIgnoresLeaseButNotSession(t *testing.T) {
	nodes := []node{{ID: "a", LastSeen: 100, ConnectedAt: 90, UptimeSeconds: 10}}
	base := bootstrapTopologyVersion(nodes, nil)
	if nodes[0].LastSeen != 100 {
		t.Fatal("hash mutated source")
	}
	nodes[0].LastSeen = 101
	nodes[0].UptimeSeconds = 11
	if got := bootstrapTopologyVersion(nodes, nil); got != base {
		t.Fatal("lease/uptime changed forwarding version")
	}
	nodes[0].ConnectedAt = 101
	if got := bootstrapTopologyVersion(nodes, nil); got == base {
		t.Fatal("new session did not change version")
	}
}
