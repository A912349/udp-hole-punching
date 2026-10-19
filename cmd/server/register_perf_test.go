package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"home-udp-mesh/internal/protocol"
)

func TestRegisterHeartbeatUsesStableRegistrationSemantics(t *testing.T) {
	s := testAuthServer(t)
	identity, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"node_id": identity.ID, "public_key": identity.Public, "nat_type": "cone",
		"role": "auto", "endpoint": "127.0.0.1:23001", "capacity": 1,
	}
	register := func() *httptest.ResponseRecorder {
		r := authRequest(http.MethodPost, "/v1/register", body)
		r.Header.Set("X-Mesh-Token", s.token)
		w := httptest.NewRecorder()
		s.register(w, r)
		return w
	}
	if first := register(); first.Code != http.StatusOK {
		t.Fatalf("initial registration = %d, body=%s", first.Code, first.Body.String())
	}
	second := register()
	if second.Code != http.StatusOK {
		t.Fatalf("heartbeat registration = %d, body=%s", second.Code, second.Body.String())
	}
	var response struct {
		TopologyChanged bool `json:"topology_changed"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.TopologyChanged {
		t.Fatal("unchanged heartbeat was reported as a topology change")
	}
	var role string
	if err := s.db.QueryRow("SELECT role FROM nodes WHERE node_id=?", identity.ID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "superpeer" {
		t.Fatalf("stable automatic role = %q, want superpeer", role)
	}
}
