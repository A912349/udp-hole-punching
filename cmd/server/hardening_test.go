package main

// These tests cover hardening behavior and regression cases.
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

func TestUsedInviteOnlyAuthorizesRecentEnrollment(t *testing.T) {
	s := testAuthServer(t)
	s.inviteAttempts = map[string][]time.Time{}
	now := time.Now().Unix()
	if _, err := s.db.Exec("INSERT INTO invites(token,created_at,expires_at,used_at) VALUES('OLDCODE',?,?,?)",
		now-2*3600, now+60, now-1800); err != nil {
		t.Fatal(err)
	}
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
		r.Header.Set("X-Mesh-Invite", "OLDCODE")
		w := httptest.NewRecorder()
		s.register(w, r)
		return w
	}
	if stale := register(); stale.Code != http.StatusUnauthorized {
		t.Fatalf("long-consumed invite status = %d, want %d; body=%s", stale.Code, http.StatusUnauthorized, stale.Body.String())
	}
	if _, err := s.db.Exec("UPDATE invites SET used_at=? WHERE token='OLDCODE'", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if fresh := register(); fresh.Code != http.StatusOK {
		t.Fatalf("recently consumed invite status = %d, want %d; body=%s", fresh.Code, http.StatusOK, fresh.Body.String())
	}
}

func TestRendezvousSessionsExpireAndAreCapped(t *testing.T) {
	s := testAuthServer(t)
	s.sessions = map[string]map[string]*rendezvousPeer{}
	old := time.Now().Add(-rendezvousSessionTTL - time.Minute)
	s.sessions["old"] = map[string]*rendezvousPeer{"a": {endpoint: "1.1.1.1:1", natType: "cone", status: "waiting", ready: make(chan struct{}), created: old}}
	s.sessions["new"] = map[string]*rendezvousPeer{"b": {endpoint: "1.1.1.1:2", natType: "cone", status: "waiting", ready: make(chan struct{}), created: time.Now()}}

	r := authRequest(http.MethodPost, "/register", map[string]any{"session": "another", "id": "c", "external": "1.1.1.1:3", "nat_type": "cone"})
	w := httptest.NewRecorder()
	s.rendezvousRegister(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("rendezvous register status = %d; body=%s", w.Code, w.Body.String())
	}
	if _, ok := s.sessions["old"]; ok {
		t.Fatal("expired rendezvous session was not pruned")
	}
	if _, ok := s.sessions["new"]; !ok {
		t.Fatal("fresh rendezvous session was pruned")
	}

	for id := 0; len(s.sessions) < rendezvousMaxSessions; id++ {
		s.sessions[string(rune(id))] = map[string]*rendezvousPeer{
			"holder": {endpoint: "1.1.1.1:9", natType: "cone", status: "waiting", ready: make(chan struct{}), created: time.Now()},
		}
	}
	flood := authRequest(http.MethodPost, "/register", map[string]any{"session": "flood", "id": "c", "external": "1.1.1.1:4", "nat_type": "cone"})
	floodResponse := httptest.NewRecorder()
	s.rendezvousRegister(floodResponse, flood)
	if floodResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("overflowing rendezvous sessions status = %d, want %d", floodResponse.Code, http.StatusTooManyRequests)
	}
}

func TestTelemetryKeepsLinkCacheUntilHealthChanges(t *testing.T) {
	s := testAuthServer(t)
	s.metrics = map[string]linkMetric{}
	identity, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	register := func(nodeID, public string) {
		r := authRequest(http.MethodPost, "/v1/register", map[string]any{
			"node_id": nodeID, "public_key": public, "nat_type": "cone",
			"role": "client", "endpoint": "127.0.0.1:23001", "capacity": 1,
		})
		r.Header.Set("X-Mesh-Token", s.token)
		w := httptest.NewRecorder()
		s.register(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("register status = %d; body=%s", w.Code, w.Body.String())
		}
	}
	register(identity.ID, identity.Public)
	register(peer.ID, peer.Public)

	telemetry := func(up bool) {
		r := authRequest(http.MethodPost, "/v1/telemetry", map[string]any{
			"node_id": identity.ID,
			"links":   []map[string]any{{"peer_id": peer.ID, "rtt_ms": 5.0, "up": up}},
		})
		r.Header.Set("X-Mesh-Token", s.token)
		w := httptest.NewRecorder()
		s.telemetry(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("telemetry status = %d; body=%s", w.Code, w.Body.String())
		}
	}

	before := s.metricStamp.Load()
	telemetry(true)
	if after := s.metricStamp.Load(); after != before+1 {
		t.Fatal("first telemetry report did not register the new link")
	}
	stable := s.metricStamp.Load()
	for i := 0; i < 3; i++ {
		telemetry(true)
	}
	if after := s.metricStamp.Load(); after != stable {
		t.Fatal("unchanged telemetry invalidated the link cache")
	}
	telemetry(false)
	if after := s.metricStamp.Load(); after != stable+1 {
		t.Fatal("link down transition did not invalidate the link cache")
	}
}

func TestConcurrentRegistrationsKeepMeshIPsUnique(t *testing.T) {
	s := testAuthServer(t)
	register := func() string {
		identity, err := protocol.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		r := authRequest(http.MethodPost, "/v1/register", map[string]any{
			"node_id": identity.ID, "public_key": identity.Public, "nat_type": "cone",
			"role": "client", "endpoint": "127.0.0.1:23001", "capacity": 1,
		})
		r.Header.Set("X-Mesh-Token", s.token)
		w := httptest.NewRecorder()
		s.register(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("register status = %d; body=%s", w.Code, w.Body.String())
		}
		var out struct {
			MeshIP string `json:"mesh_ip"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.MeshIP
	}
	done := make(chan string, 8)
	for i := 0; i < 8; i++ {
		go func() { done <- register() }()
	}
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		ip := <-done
		if ip == "" {
			t.Fatal("registration did not assign a mesh IP")
		}
		if seen[ip] {
			t.Fatalf("mesh IP %s was assigned twice", ip)
		}
		seen[ip] = true
	}
}
