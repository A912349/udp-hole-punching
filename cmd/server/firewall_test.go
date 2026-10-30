package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// insertFirewallNode creates a minimal node row so access-control checks pass.
func insertFirewallNode(t *testing.T, s *server, id string) {
	t.Helper()
	_, err := s.db.Exec(`INSERT INTO nodes(node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		id, "pub-"+id, "full_cone", "client", "198.51.100.7:4242", "auto", 1, 1, time.Now().Unix(), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
}

func firewallRequest(s *server, method, target string, body any) (*http.Request, *httptest.ResponseRecorder) {
	r := authRequest(method, target, body)
	r.Header.Set("X-Mesh-Token", s.token)
	return r, httptest.NewRecorder()
}

func TestFirewallDefaultPolicyIsAllowAll(t *testing.T) {
	s := testAuthServer(t)
	insertFirewallNode(t, s, "fw-node-a")

	r, rec := firewallRequest(s, http.MethodGet, "/v1/admin/nodes/fw-node-a/firewall", nil)
	s.adminFirewallGet(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("firewall GET status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var fw firewallConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &fw); err != nil {
		t.Fatalf("firewall GET body is not JSON: %v", err)
	}
	if fw.Mode != "allow_all" || len(fw.Ports) != 0 {
		t.Fatalf("expected allow_all with no ports, got %+v", fw)
	}
}

func TestFirewallValidation(t *testing.T) {
	s := testAuthServer(t)
	insertFirewallNode(t, s, "fw-node-b")

	cases := []struct {
		name   string
		body   map[string]any
		status int
	}{
		{"unknown mode", map[string]any{"mode": "stealth", "ports": []string{}}, http.StatusBadRequest},
		{"port out of range", map[string]any{"mode": "whitelist", "ports": []string{"70000/tcp"}}, http.StatusBadRequest},
		{"non-numeric port", map[string]any{"mode": "whitelist", "ports": []string{"http/tcp"}}, http.StatusBadRequest},
		{"unsupported protocol", map[string]any{"mode": "whitelist", "ports": []string{"80/smtp"}}, http.StatusBadRequest},
		{"valid whitelist", map[string]any{"mode": "whitelist", "ports": []string{"80/udp", "80/udp", "443", "53/UDP", "80/tcp"}}, http.StatusOK},
	}
	var fw firewallConfig
	var lastBody []byte
	for _, tc := range cases {
		r, rec := firewallRequest(s, http.MethodPut, "/v1/admin/nodes/fw-node-b/firewall", tc.body)
		s.adminFirewallSet(rec, r)
		if rec.Code != tc.status {
			t.Fatalf("%s: status = %d, want %d, body=%s", tc.name, rec.Code, tc.status, rec.Body.String())
		}
		lastBody = rec.Body.Bytes()
	}
	// The stored list must be normalized: bare port expands to tcp+udp,
	// protocol is lowercased, duplicates collapse, entries are sorted.
	if err := json.Unmarshal(lastBody, &fw); err != nil {
		t.Fatalf("final PUT body is not JSON: %v", err)
	}
	want := []string{"443/tcp", "443/udp", "53/udp", "80/tcp", "80/udp"}
	if fw.Mode != "whitelist" || len(fw.Ports) != len(want) {
		t.Fatalf("normalized firewall = %+v, want mode=whitelist ports=%v", fw, want)
	}
	for i := range want {
		if fw.Ports[i] != want[i] {
			t.Fatalf("ports[%d] = %q, want %q (full list %v)", i, fw.Ports[i], want[i], fw.Ports)
		}
	}

	// GET returns the persisted policy, not just the PUT echo.
	r, rec := firewallRequest(s, http.MethodGet, "/v1/admin/nodes/fw-node-b/firewall", nil)
	s.adminFirewallGet(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("firewall GET after PUT status = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &fw); err != nil {
		t.Fatalf("firewall GET after PUT is not JSON: %v", err)
	}
	if fw.Mode != "whitelist" || len(fw.Ports) != len(want) {
		t.Fatalf("persisted firewall = %+v, want whitelist with %d ports", fw, len(want))
	}
}

func TestFirewallChangeBumpsBootstrapVersion(t *testing.T) {
	s := testAuthServer(t)
	insertFirewallNode(t, s, "fw-node-c")
	firewall := s.loadFirewall("fw-node-c")
	if firewall.Mode != "allow_all" {
		t.Fatalf("default firewall mode = %q", firewall.Mode)
	}
	if _, err := s.db.Exec(`INSERT INTO node_firewall(node_id,mode,ports,updated_at) VALUES('fw-node-c','whitelist','["22/tcp"]',?)`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if fw := s.loadFirewall("fw-node-c"); fw.Mode != "whitelist" || len(fw.Ports) != 1 || fw.Ports[0] != "22/tcp" {
		t.Fatalf("loadFirewall after change = %+v", fw)
	}
	// The firewall must be part of the snapshot hash so nodes notice the
	// change through their conditional bootstrap: the same nodes/links view
	// must produce different versions for different firewall policies.
	encodedA, _ := json.Marshal(firewallConfig{Mode: "allow_all"})
	encodedB, _ := json.Marshal(s.loadFirewall("fw-node-c"))
	if string(encodedA) == string(encodedB) {
		t.Fatal("firewall encoding did not change after policy update")
	}
}
